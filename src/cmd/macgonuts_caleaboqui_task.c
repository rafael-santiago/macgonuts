/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_caleaboqui_task.h>
#include <cmd/hooks/macgonuts_caleaboqui_init_hook.h>
#include <cmd/hooks/macgonuts_caleaboqui_deinit_hook.h>
#include <cmd/hooks/macgonuts_caleaboqui_done_hook.h>
#include <cmd/macgonuts_option.h>
#include <cmd/macgonuts_misc_utils.h>
#include <macgonuts_status_info.h>
#include <macgonuts_thread.h>
#include <macgonuts_socket.h>
#include <macgonuts_socket_common.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_spoof.h>
#include <macgonuts_metaspoofer.h>

#define MACGONUTS_CALEABOQUI_CIDR_SPOOF_NR 5

#define MACGONUTS_CALEABOQUI_SOCKET_TIMEO 50000

struct caleaboqui_td_task_ctx {
    uint8_t first_addr[16];
    uint8_t last_addr[16];
    char gw_addr[256];
    size_t gw_addr_size;
    int is_cidr;
    const char *lo_iface;
    int undo_spoof;
    int hide_my_ass;
    size_t spoof_threads;
    int is_busy;
    int *should_exit;
    struct macgonuts_spoofing_guidance_ctx spfgd;
    struct caleaboqui_td_task_ctx *next;
};

static int g_ShouldExit = 0;

static struct caleaboqui_td_task_ctx *alloc_caleaboqui_td_tasks_ctx(const size_t target_addrs_nr);

static void free_caleaboqui_td_tasks_ctx(struct caleaboqui_td_task_ctx *td_tasks);

static int fill_up_caleaboqui_td_tasks_ctx(struct caleaboqui_td_task_ctx *td_tasks,
                                           const char **target_addrs, const size_t target_addrs_nr,
                                           const char *lo_iface, const int undo_spoof, const int hide_my_ass,
                                           const uint64_t timeout, const int64_t fake_pkts_amount,
                                           const size_t spoof_threads);

static int do_caleaboqui(struct caleaboqui_td_task_ctx *td_tasks, const size_t targets_addr_nr);

static void *do_caleaboqui_addr(void *args);

static void *do_caleaboqui_cidr(void *args);

static inline void set_task_to_busy(struct caleaboqui_td_task_ctx *td_task);

static inline void set_task_to_idle(struct caleaboqui_td_task_ctx *td_task);

static inline void set_task_is_busy_to(struct caleaboqui_td_task_ctx *td_task, const int value);

static int should_exit(struct caleaboqui_td_task_ctx *td_tasks);

static void sigint_watchdog(int signo);

int macgonuts_caleaboqui_task(void) {
    int err = EXIT_FAILURE;
    const char *lo_iface = NULL;
    char **target_addrs = NULL;
    size_t target_addrs_nr = 0;
    int undo_spoof = macgonuts_get_bool_option("undo-spoof", 0);
    int hide_my_ass = macgonuts_get_bool_option("hide-my-ass", 0);
    const char *timeout = NULL;
    const char *fake_pkts_amount = NULL;
    const char *spoof_threads = NULL;
    struct caleaboqui_td_task_ctx *td_tasks = NULL;
    size_t spoof_threads_nr = 0;

    lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    target_addrs = macgonuts_get_array_option("target-addrs", NULL, &target_addrs_nr);
    if (target_addrs == NULL) {
        macgonuts_si_error("--target-addrs option is missing.\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    td_tasks = alloc_caleaboqui_td_tasks_ctx(target_addrs_nr);
    if (td_tasks == NULL) {
        macgonuts_si_error("unable to allocate thread context(s).\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    timeout = macgonuts_get_option("timeout", "0");
    if (!macgonuts_is_valid_number(timeout)) {
        macgonuts_si_error("--timeout has invalid number.\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    fake_pkts_amount = macgonuts_get_option("fake-pkts-amount", "0");
    if (!macgonuts_is_valid_number(fake_pkts_amount)) {
        macgonuts_si_error("--fake-pkts-amount has invalid number.\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    spoof_threads = macgonuts_get_option("spoof-threads", "1");
    if (!macgonuts_is_valid_number(spoof_threads)) {
        macgonuts_si_error("--spoof-threads has invalid_number.\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    spoof_threads_nr = atoi(spoof_threads);
    if (spoof_threads_nr < 1) {
        macgonuts_si_error("--spoof-thread must be a number greater or equal than one.\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    if (fill_up_caleaboqui_td_tasks_ctx(td_tasks,
                                        (const char **)target_addrs, target_addrs_nr,
                                        lo_iface, undo_spoof, hide_my_ass,
                                        atoi(timeout),
                                        atoi(fake_pkts_amount),
                                        spoof_threads_nr) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to fill up thread context(s).\n");
        goto macgonuts_caleaboqui_task_epilogue;
    }

    err = do_caleaboqui(td_tasks, target_addrs_nr);

macgonuts_caleaboqui_task_epilogue:

    if (td_tasks != NULL) {
        free_caleaboqui_td_tasks_ctx(td_tasks);
    }

    if (target_addrs != NULL) {
        macgonuts_free_array_option_value(target_addrs, target_addrs_nr);
    }

    return err;
}

int macgonuts_caleaboqui_task_help(void) {
    macgonuts_si_print("use: macgonuts caleaboqui | shh --lo-iface=<label> "
                       "--target-addrs=<ip4|ip6|cidr4|cidr6 list>\n"
                       "                                "
                       "[--undo-spoof --hide-my-ass --timeout=<ms> --fake-pkts-amount=<ms> --spoof-threads=<n>]\n");
    return EXIT_SUCCESS;
}

static struct caleaboqui_td_task_ctx *alloc_caleaboqui_td_tasks_ctx(const size_t target_addrs_nr) {
    struct caleaboqui_td_task_ctx *tp = NULL, *tp_end = NULL;
    size_t td_tasks_in_bytes = sizeof(struct caleaboqui_td_task_ctx) * target_addrs_nr;
    struct caleaboqui_td_task_ctx *td_tasks = (struct caleaboqui_td_task_ctx *)malloc(td_tasks_in_bytes);
    if (td_tasks == NULL) {
        return NULL;
    }

    memset(td_tasks, 0, td_tasks_in_bytes);

    tp = td_tasks;
    tp_end = tp + target_addrs_nr;

    while (tp != tp_end) {
        tp++;
        tp[-1].next = (tp != tp_end) ? tp : NULL;
    }

    return td_tasks;
}

static void free_caleaboqui_td_tasks_ctx(struct caleaboqui_td_task_ctx *td_tasks) {
    struct caleaboqui_td_task_ctx *p, *t;
    for (p = t = td_tasks; t; p = t) {
        t = t->next;
        macgonuts_release_spoof_layers_ctx(&p->spfgd.layers);
        if (p->spfgd.handles.wire > -1) {
            macgonuts_release_socket(p->spfgd.handles.wire);
            p->spfgd.handles.wire = -1;
        }
    }
    free(td_tasks);
}

static int fill_up_caleaboqui_td_tasks_ctx(struct caleaboqui_td_task_ctx *td_tasks,
                                           const char **target_addrs, const size_t target_addrs_nr,
                                           const char *lo_iface, const int undo_spoof, const int hide_my_ass,
                                           const uint64_t timeout, const int64_t fake_pkts_amount,
                                           const size_t spoof_threads) {
    int err = EXIT_FAILURE;
    struct caleaboqui_td_task_ctx *tp = NULL;
    size_t t = 0;
    char gw_addr[2][256] = { "", "" };
    uint8_t addr[16];
    size_t addr_size;
    int ip_v = 0, cidr_v = 0;
    size_t target_addr_size = 0;
    char temp_addr[256] = "";
    const char *target_addr = NULL;
    struct timeval tv;

    if (macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 4, lo_iface) == EXIT_SUCCESS) {
        if (macgonuts_raw_ip2literal(gw_addr[1], sizeof(gw_addr[1]) - 1, &addr[0], 4) != EXIT_SUCCESS) {
            macgonuts_si_error("unable to convert ipv4 address.\n");
            return EXIT_FAILURE;
        }
    }

    if (macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 6, lo_iface) == EXIT_SUCCESS) {
        if (macgonuts_raw_ip2literal(gw_addr[0], sizeof(gw_addr[0]) - 1, &addr[0], 16) != EXIT_SUCCESS) {
            macgonuts_si_error("unable to convert ipv6 address.\n");
            return EXIT_FAILURE;
        }
    }

    if (gw_addr[0][0] == 0 && gw_addr[0][1] == 0) {
        macgonuts_si_error("interface %s is not well addressed.\n", lo_iface);
        return EXIT_FAILURE;
    }

    err = EXIT_SUCCESS;

    memset(&tv, 0, sizeof(tv));
    tv.tv_usec = MACGONUTS_CALEABOQUI_SOCKET_TIMEO;

    for (tp = td_tasks; tp != NULL && err == EXIT_SUCCESS; tp = tp->next, t++) {
        err = macgonuts_mutex_init(&tp->spfgd.handles.lock);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_error("when trying to initialize mutex.\n");
            continue;
        }

        ip_v = cidr_v = -1;
        target_addr_size = strlen(target_addrs[t]);
        ip_v = macgonuts_get_ip_version(target_addrs[t], target_addr_size);
        if (ip_v == -1) {
            cidr_v = macgonuts_get_cidr_version(target_addrs[t], target_addr_size);
        }

        if (ip_v == -1 && cidr_v == -1) {
            macgonuts_si_error("%s is an invalid ip address or cidr.\n", target_addrs[t]);
            err = EXIT_FAILURE;
            continue;
        }

        tp->spfgd.layers.proto_addr_size = (ip_v == 4 || cidr_v == 4) ? 4 : 16;
        tp->lo_iface = lo_iface;
        tp->undo_spoof = undo_spoof;
        tp->hide_my_ass = hide_my_ass;
        tp->spoof_threads = spoof_threads;
        tp->spfgd.spoofing.timeout = timeout;
        tp->spfgd.spoofing.total = fake_pkts_amount;

        tp->spfgd.handles.wire = macgonuts_create_socket(lo_iface, (cidr_v == -1));
        if (tp->spfgd.handles.wire == -1) {
            macgonuts_si_error("unable to create socket.\n");
            err = EXIT_FAILURE;
            continue;
        }

        if (cidr_v > -1) {
            // INFO(Rafael): When CIDRing we will use a shorter timeout to speed up the range traverse.
            //               Anyway, if you want to cut off the internet access from a host, target
            //               it by "unicasting" it instead of inferring the target throught network
            //               CIDR.
#if defined(__linux__)
            setsockopt(tp->spfgd.handles.wire, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(tp->spfgd.handles.wire, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#elif defined(__FreeBSD__)
            ioctl(tp->spfgd.handles.wire, BIOCSRTIMEOUT, &tv);
#else
# error Some code wanted.
#endif // defined(__linux__)

        }

        tp->spfgd.hooks.init = tp->spfgd.hooks.deinit = tp->spfgd.hooks.redirect = NULL;
        tp->spfgd.hooks.done = macgonuts_caleaboqui_done_hook;

        if (ip_v > -1) {
            tp->is_cidr = 0;
            target_addr = &target_addrs[t][0];
        } else {
            tp->is_cidr = 1;
            ip_v = cidr_v;
            err = macgonuts_get_raw_cidr(&tp->first_addr[0],
                                         &tp->last_addr[0],
                                         target_addrs[t], target_addr_size);
            if (err != EXIT_SUCCESS) {
                continue;
            }
            err = macgonuts_raw_ip2literal(temp_addr,
                                           sizeof(temp_addr) - 1,
                                           &tp->first_addr[0], (cidr_v != 4) ? 16 : 4);
            if (err != EXIT_SUCCESS) {
                macgonuts_si_error("unable to convert %s address.\n", (cidr_v != 4) ? "ipv6" : "ipv4");
                continue;
            }
            target_addr = &temp_addr[0];
            target_addr_size = strlen(temp_addr);
        }

        if (cidr_v == -1) {
            tp->spfgd.layers.always_do_pktcraft = hide_my_ass;
            err = macgonuts_get_spoof_layers_info(tp->spfgd.handles.wire,
                                                  &tp->spfgd.layers,
                                                  target_addr, target_addr_size,
                                                  gw_addr[ip_v == 4], strlen(gw_addr[ip_v == 4]),
                                                  lo_iface);
        } else {
            tp->gw_addr_size = snprintf(tp->gw_addr, sizeof(tp->gw_addr), "%s", gw_addr[ip_v == 4]);
        }

        tp->should_exit = &g_ShouldExit;
    }

    return err;
}

static int do_caleaboqui(struct caleaboqui_td_task_ctx *td_tasks, const size_t targets_addr_nr) {
    size_t t = 0;
    struct caleaboqui_td_task_ctx *tp = td_tasks;
    macgonuts_thread_t *td = (macgonuts_thread_t *)malloc(sizeof(macgonuts_thread_t) * targets_addr_nr);
    char target_addr[256];

    if (td == NULL) {
        macgonuts_si_error("unable to allocate thread array.\n");
        return EXIT_FAILURE;
    }

    if (macgonuts_caleaboqui_init_hook(NULL, NULL, 0) != EXIT_SUCCESS) {
        goto do_caleaboqui_epilogue;
    }

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    while (!should_exit(td_tasks)) {
        macgonuts_mutex_lock(&tp->spfgd.handles.lock);
        if (!tp->is_busy
            && macgonuts_create_thread(&td[t],
                                       (tp->is_cidr) ? do_caleaboqui_cidr : do_caleaboqui_addr,
                                       tp) != EXIT_SUCCESS) {
            macgonuts_si_warn("error when trying to create spoofing thread, retrying...\n");
            continue;
        }
        macgonuts_mutex_unlock(&tp->spfgd.handles.lock);
        tp = (tp->next != NULL) ? tp->next : td_tasks;
        t = (tp == td_tasks) ? 0 : t + 1;
        usleep(10);
    }

    for (t = 0; t < targets_addr_nr; t++) {
        macgonuts_thread_join(&td[t], NULL);
    }

    for (tp = td_tasks; tp != NULL; tp = tp->next) {
        if (tp->undo_spoof) {
            switch (tp->is_cidr) {
                case 1:
                    macgonuts_si_warn("sorry but hosts inferred from cidr have no access to Internet restablished, "
                                      "just skipping them up.\n");
                    break;
                default:
                    if (macgonuts_undo_spoof(tp->spfgd.handles.wire, &tp->spfgd.layers) == EXIT_SUCCESS) {
                        macgonuts_raw_ip2literal(target_addr,
                                                 sizeof(target_addr) - 1,
                                                 &tp->spfgd.layers.tg_proto_addr[0],
                                                 tp->spfgd.layers.proto_addr_size);
                        macgonuts_si_info("access to Internet from `%s` was restablished.\n", target_addr);
                    } else {
                        macgonuts_si_warn("access to Internet from `%s` could not be restablished.\n", target_addr);
                    }
                    break;
            }
        }
    }

do_caleaboqui_epilogue:

    if (td != NULL) {
        free(td);
    }

    return macgonuts_caleaboqui_deinit_hook(NULL, NULL, 0);
}

static void *do_caleaboqui_addr(void *args) {
    struct caleaboqui_td_task_ctx *td_task = (struct caleaboqui_td_task_ctx *)args;
    char target[256];

    set_task_to_busy(td_task);

    if (memcmp(&td_task->spfgd.layers.tg_proto_addr[0],
               &td_task->spfgd.layers.lo_proto_addr[0],
               td_task->spfgd.layers.proto_addr_size) == 0) {
        macgonuts_si_warn("skipping `%s`, it is your host...\n", td_task->spfgd.usrinfo.tg_address);
        goto do_caleaboqui_addr_epilogue;
    }

    if (td_task->hide_my_ass) {
        macgonuts_getrandom_raw_ether_addr(&td_task->spfgd.layers.lo_hw_addr[0],
                                           sizeof(td_task->spfgd.layers.lo_hw_addr));
    }

    macgonuts_raw_ip2literal(target,
                             sizeof(target) - 1,
                             &td_task->spfgd.layers.tg_proto_addr[0],
                             td_task->spfgd.layers.proto_addr_size);

    td_task->spfgd.usrinfo.tg_address = &target[0];

    if (macgonuts_run_metaspoofer(&td_task->spfgd) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to spoof target `%s`.\n", target);
    }

do_caleaboqui_addr_epilogue:

    if (td_task->spfgd.spoofing.total > 0 && !should_exit(td_task)) {
        td_task->spfgd.spoofing.abort = 0;
    }

    set_task_to_idle(td_task);

    return NULL;
}

static void *do_caleaboqui_cidr(void *args) {
    struct caleaboqui_td_task_ctx *td_task = (struct caleaboqui_td_task_ctx *)args;
    struct caleaboqui_td_task_ctx *td_aux_tasks = NULL;
    struct caleaboqui_td_task_ctx *tp = NULL;
    uint8_t curr_addr[16];
    uint8_t sentinel_addr[16];
    size_t addr_size = td_task->spfgd.layers.proto_addr_size;
    size_t t;
    macgonuts_thread_t *td = NULL;
    char target_addr[256];
    size_t target_addr_size;
    int err = EXIT_FAILURE;
    set_task_to_busy(td_task);

    td = (macgonuts_thread_t *)malloc(sizeof(macgonuts_thread_t) * td_task->spoof_threads);
    if (td == NULL) {
        macgonuts_si_error("unable to allocate thread array.\n");
        goto do_caleaboqui_cidr_epilogue;
    }

    td_aux_tasks = alloc_caleaboqui_td_tasks_ctx(td_task->spoof_threads);
    if (td_aux_tasks == NULL) {
        macgonuts_si_error("unable to allocate auxiliary thread contexts.\n");
        goto do_caleaboqui_cidr_epilogue;
    }

    macgonuts_mutex_lock(&td_task->spfgd.handles.lock);

    for (tp = td_aux_tasks; tp != NULL; tp = tp->next) {
        tp->is_cidr = 0;
        tp->spfgd.layers.proto_addr_size = td_task->spfgd.layers.proto_addr_size;
        tp->lo_iface = td_task->lo_iface;
        tp->undo_spoof = td_task->undo_spoof;
        tp->hide_my_ass = td_task->hide_my_ass;
        macgonuts_mutex_init(&tp->spfgd.handles.lock);
        tp->spfgd.handles.wire = td_task->spfgd.handles.wire;
        tp->spfgd.spoofing.timeout = td_task->spfgd.spoofing.timeout;
        tp->spfgd.spoofing.total = (td_task->spfgd.spoofing.total > 0) ?
                                     td_task->spfgd.spoofing.total :
                                    MACGONUTS_CALEABOQUI_CIDR_SPOOF_NR;
        tp->spfgd.spoofing.abort = 0;
        memcpy(&tp->spfgd.hooks, &td_task->spfgd.hooks, sizeof(td_task->spfgd.hooks));
        tp->should_exit = td_task->should_exit;
    }

    macgonuts_mutex_unlock(&td_task->spfgd.handles.lock);

    do {
        memcpy(curr_addr, td_task->first_addr, addr_size);
        memcpy(sentinel_addr, td_task->last_addr, addr_size);
        macgonuts_inc_raw_ip(curr_addr, addr_size);
        macgonuts_inc_raw_ip(sentinel_addr, addr_size);
        tp = td_aux_tasks;
        t = 0;
        while (memcmp(curr_addr, sentinel_addr, addr_size) != 0
               && !should_exit(td_task)) {

            if (tp != NULL && t < td_task->spoof_threads) {
                err = macgonuts_raw_ip2literal(target_addr, sizeof(target_addr) - 1,
                                               curr_addr, addr_size);
                if (err != EXIT_SUCCESS) {
                    continue;
                }
                target_addr_size = strlen(target_addr);
                if (strcmp(target_addr, td_task->gw_addr) != 0) {
                    err = macgonuts_get_spoof_layers_info(tp->spfgd.handles.wire,
                                                          &tp->spfgd.layers,
                                                          target_addr, target_addr_size,
                                                          td_task->gw_addr, td_task->gw_addr_size,
                                                          tp->lo_iface);
                    if (err == EXIT_SUCCESS) {
                        // INFO(Rafael): In this way we will not allocate anything after spoofing.
                        //               Spoofed frames always will be freeded.
                        tp->spfgd.layers.always_do_pktcraft = 1;
                        if (macgonuts_create_thread(&td[t], do_caleaboqui_addr, tp) != EXIT_SUCCESS) {
                            macgonuts_si_error("error when trying to create spoofing thread, retrying...\n");
                            continue;
                        }
                        tp = tp->next;
                        t++;
                    } else {
                        macgonuts_si_warn("`%s` seems down, just skipping it...\n", target_addr);
                    }
                } else {
                    macgonuts_si_warn("`%s` is the network gateway, just skipping it...\n", target_addr);
                }
                macgonuts_inc_raw_ip(curr_addr, addr_size);
            } else {
                macgonuts_si_warn("all spoofing threads are occupied, waiting for a free one to continue...\n");
                for (t = 0; t < td_task->spoof_threads; t++) {
                    macgonuts_thread_join(&td[t], NULL);
                }
                tp = td_aux_tasks;
                t = 0;
            }
        }
    } while (!should_exit(td_task));

do_caleaboqui_cidr_epilogue:

    if (td_aux_tasks != NULL) {
        for (tp = td_aux_tasks; tp != NULL; tp = tp->next) {
            macgonuts_mutex_destroy(&tp->spfgd.handles.lock);
        }
        // INFO(Rafael): Here it is right. We do not need to free the allocated resources
        //               inside each item of this linked list, they are just quick copies
        //               from relevant data into td_task.
        free(td_aux_tasks);
    }

    if (td != NULL) {
        free(td);
    }
    set_task_to_idle(td_task);
    return NULL;
}

static inline void set_task_to_busy(struct caleaboqui_td_task_ctx *td_task) {
    set_task_is_busy_to(td_task, 1);
}

static inline void set_task_to_idle(struct caleaboqui_td_task_ctx *td_task) {
    set_task_is_busy_to(td_task, 0);
}

static inline void set_task_is_busy_to(struct caleaboqui_td_task_ctx *td_task, const int value) {
    macgonuts_mutex_lock(&td_task->spfgd.handles.lock);
    td_task->is_busy = value;
    macgonuts_mutex_unlock(&td_task->spfgd.handles.lock);
}

static int should_exit(struct caleaboqui_td_task_ctx *td_tasks) {
    int should = 0;
    struct caleaboqui_td_task_ctx *tp = td_tasks;
    while (!should && tp != NULL) {
        macgonuts_mutex_lock(&tp->spfgd.handles.lock);
        should = *tp->should_exit;
        macgonuts_mutex_unlock(&tp->spfgd.handles.lock);
        tp = tp->next;
    }
    if (should) {
        tp = td_tasks;
        while (tp != NULL) {
            macgonuts_mutex_lock(&tp->spfgd.handles.lock);
            tp->spfgd.spoofing.abort = 1;
            macgonuts_mutex_unlock(&tp->spfgd.handles.lock);
            tp = tp->next;
            usleep(10);
        }
    }
    return should;
}

static void sigint_watchdog(int signo) {
    g_ShouldExit = 1;
}

#undef MACGONUTS_CALEABOQUI_CIDR_SPOOF_NR

#undef MACGONUTS_CALEABOQUI_SOCKET_TIMEO
