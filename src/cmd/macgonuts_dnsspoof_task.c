/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_dnsspoof_task.h>
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
#include <macgonuts_status_info.h>

#define DEFAULT_ETC_HOAX_PATH "/usr/local/share/macgonuts/etc/hoax"

struct dnsspoof_task_ctx {
    macgonuts_etc_hoax_handle *etc_hoax_handle;
    size_t hoax_ttl;
    char lo_iface[256];
    char tg_address[256];
    char spoof_address[256];
    struct macgonuts_spoofing_guidance_ctx spfgd;
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

int macgonuts_dnsspoof_task(void) {
    struct dnsspoof_task_ctx **dnsspoof_tasks = NULL;
    size_t tasks_nr = 0;
    const char *lo_iface = NULL;
    const char *etc_hoax = NULL;
    macgonuts_etc_hoax_handle *etc_hoax_handle = NULL;
    char **target_addrs = NULL;
    size_t target_addrs_nr = 0;
    const char *hoax_ttl = NULL;
    size_t hoax_ttl_value = 0;
    char **dns_addrs = NULL;
    size_t dns_addrs_nr = 0;
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

    dns_addrs = macgonuts_get_array_option("dns-addrs", NULL, &dns_addrs_nr);

    dnsspoof_tasks = alloc_dnsspoof_task_contexts(&tasks_nr,
                                                  lo_iface,
                                                  (const char **)target_addrs, target_addrs_nr,
                                                  NULL,
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

    return err;
}

int macgonyts_dnspoof_task_help(void) {
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
    uint8_t gw_addr[16] = { 0 };
    size_t gw_addr_size = 0;
    uint8_t iface_netmask[2][16] = { 0 };
    size_t iface_size = 0;
    int ip_version;
    uint8_t iface_addr[2][16] = { 0 };
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

    assert(tasks_nr != NULL
           && iface != NULL
           && target_addrs != NULL
           && target_addrs_nr > 0
           && etc_hoax_handle != NULL
           && hoax_ttl > 0);

    *tasks_nr = 0;

    iface_size = strlen(iface);
    if (macgonuts_get_gateway_addr_info(iface_buf, sizeof(iface_buf), &gw_addr[0], &gw_addr_size) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get gateway address.\n");
        return NULL;
    }

    if (macgonuts_get_netmask_from_iface(iface, iface_size, &iface_netmask[1][0], 4) != EXIT_SUCCESS
        && macgonuts_get_netmask_from_iface(iface, iface_size, &iface_netmask[0][0], 6) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get network mask.\n");
        return NULL;
    }

    if (macgonuts_get_addr_from_iface_unix(iface_addr_buf, sizeof(iface_addr_buf), 4, iface_buf) == EXIT_SUCCESS
        && macgonuts_get_raw_ip_addr(&iface_addr[1][0], 4, iface_addr_buf, strlen(iface_addr_buf)) == EXIT_SUCCESS) {
        iface_ip_support = kIPv4;
    }

    if (macgonuts_get_addr_from_iface_unix(iface_addr_buf, sizeof(iface_addr_buf), 6, iface_buf) == EXIT_SUCCESS
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
        (*tp)->hoax_ttl = hoax_ttl;
        (*tp)->spfgd.hooks.init = macgonuts_dnsspoof_init_hook;
        (*tp)->spfgd.hooks.deinit = macgonuts_dnsspoof_deinit_hook;
        (*tp)->spfgd.hooks.done = macgonuts_dnsspoof_done_hook;
        (*tp)->spfgd.hooks.redirect = macgonuts_dnsspoof_redirect_hook;
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
            if (tp == tasks) {
                if (macgonuts_raw_ip2literal(&(*tp)->spoof_address[0], sizeof((*tp)->spoof_address) - 1,
                                             gw_addr, gw_addr_size) != EXIT_SUCCESS) {
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
            if (macgonuts_get_spoof_layers_info((*tp)->spfgd.handles.wire,
                                                &(*tp)->spfgd.layers,
                                                (*tp)->tg_address, target_addr_size,
                                                (*tp)->spoof_address, lit_gw_addr_size,
                                                (*tp)->lo_iface) != EXIT_SUCCESS) {
                macgonuts_si_error("unable to fill up task's spoofing layer information.\n");
                goto alloc_dnsspoof_tasks_contexts_epilogue;
            }
            (*tp)->spfgd.layers.spoofing_gateway = 1;
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
            dns_addr = dns_addrs;
            while (dns_addr != dns_addrs_end && tp != tp_end) {
                if (target_addr == target_addrs) {
                    d = (dns_addrs_end - dns_addrs) - (dns_addrs_end - dns_addr);
                    dns_ip_version[d] = macgonuts_get_ip_version(*dns_addr, dns_addr_size);
                    if ((dns_ip_version[d] != 4 && dns_ip_version[d] != 6)
                        || (dns_ip_version[d] == 4 && !(iface_ip_support & kIPv4))
                        || (dns_ip_version[d] == 6 && !(iface_ip_support & kIPv6))) {
                        macgonuts_si_error("dns address `%s` seems invalid.\n", *dns_addr);
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
                    if (macgonuts_raw_ip2literal(&lit_gw_addr[0], sizeof(lit_gw_addr) - 1,
                                                 gw_addr, gw_addr_size) != EXIT_SUCCESS) {
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
                                                           &iface_addr[ip_version == 4][0],
                                                           &iface_netmask[ip_version == 4][0],
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
                    if (macgonuts_get_spoof_layers_info((*tp)->spfgd.handles.wire,
                                                        &(*tp)->spfgd.layers,
                                                        (*tp)->tg_address, target_addr_size,
                                                        (*tp)->spoof_address, dns_addr_size,
                                                        (*tp)->lo_iface) != EXIT_SUCCESS) {
                        macgonuts_si_error("unable to fill up task's spoofing layer information.\n");
                        goto alloc_dnsspoof_tasks_contexts_epilogue;
                    }
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
    // TODO(Rafael): Install a SIGINT watchdog, run the tasks, join waiting for each one.
    return ENOTSUP;
}

#undef DEFAULT_ETC_HOAX_PATH
