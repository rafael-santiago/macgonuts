/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_isolate_task.h>
#include <cmd/hooks/macgonuts_isolate_init_hook.h>
#include <cmd/hooks/macgonuts_isolate_deinit_hook.h>
#include <cmd/hooks/macgonuts_isolate_done_hook.h>
#include <cmd/macgonuts_option.h>
#include <cmd/macgonuts_misc_utils.h>
#include <macgonuts_status_info.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_socket.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_spoof.h>

static struct macgonuts_spoofing_guidance_ctx g_Spfgd = { 0 };

static int g_URandomFd = -1;

static int fill_up_lo_info(void);

static int fill_up_tg_info(void);

static int do_isolate(void);

static int cut_off_route_to(const uint8_t *first_addr, const uint8_t *last_addr);

static void get_random_mac(uint8_t *hw_addr, const size_t hw_addr_size);

static int is_valid_no_route_to(const char **no_route_to, const size_t no_route_to_nr);

static void sigint_watchdog(int signo);

int macgonuts_isolate_task(void) {
    int err = EFAULT;
    char **no_route_to = NULL;
    size_t no_route_to_nr = 0;
    const char *timeout = NULL;

    g_Spfgd.usrinfo.lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (g_Spfgd.usrinfo.lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        return EXIT_FAILURE;
    }

    g_Spfgd.usrinfo.tg_address = macgonuts_get_option("isle-addr", NULL);
    if (g_Spfgd.usrinfo.tg_address == NULL) {
        macgonuts_si_error("--isle-addr option is missing.\n");
        return EXIT_FAILURE;
    }

    no_route_to = macgonuts_get_array_option("no-route-to", NULL, &no_route_to_nr);

    if (no_route_to == NULL || no_route_to_nr == 0) {
        macgonuts_si_error("--no-route-to option is missing.\n");
        return EXIT_FAILURE;
    }

    err = fill_up_lo_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get local host's network information.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    g_Spfgd.handles.wire = macgonuts_create_socket(g_Spfgd.usrinfo.lo_iface, 1);
    if (g_Spfgd.handles.wire == -1) {
        macgonuts_si_error("unable to create socket.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    err = fill_up_tg_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get isle host's network information.\n");
        goto macgonuts_isolate_task_epilogue;

    }

    if (is_valid_no_route_to((const char **)no_route_to, no_route_to_nr)) {
        macgonuts_si_error("--no-route-to has invalid data.\n");
        err = EXIT_FAILURE;
        goto macgonuts_isolate_task_epilogue;
    }

    g_Spfgd.metainfo.arg[0] = no_route_to;
    g_Spfgd.metainfo.arg[1] = &no_route_to_nr;

    timeout = macgonuts_get_option("timeout", NULL);
    if (timeout != NULL) {
        if (!macgonuts_is_valid_number(timeout)) {
            macgonuts_si_error("--timeout has invalid number.\n");
            goto macgonuts_isolate_task_epilogue;
        }
        g_Spfgd.spoofing.timeout = atoi(timeout);
    }

    g_Spfgd.hooks.init = macgonuts_isolate_init_hook;
    g_Spfgd.hooks.deinit = macgonuts_isolate_deinit_hook;
    g_Spfgd.hooks.done = macgonuts_isolate_done_hook;

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    err = do_isolate();

macgonuts_isolate_task_epilogue:

    if (no_route_to != NULL) {
        macgonuts_free_array_option_value(no_route_to, no_route_to_nr);
    }

    macgonuts_release_spoof_layers_ctx(&g_Spfgd.layers);

    return err;
}

int macgonuts_isolate_task_help(void) {
    macgonuts_si_print("use: macgonuts isolate --lo-iface=<label>\n"
                       "                       --isle-addr=<ip4|ip6>\n"
                       "                       --no-route-to=<(ip4|ip6|cidr4|cidr6)_0>,...,<(ip4|ip6|cidr4|cidr6)_n>\n"
                       "                      [--keep-flooding --timeout=<mss>]\n");
    return EXIT_SUCCESS;
}

static int do_isolate(void) {
    const char **no_route_to = (const char **)g_Spfgd.metainfo.arg[0];
    const size_t *no_route_to_nr = (const size_t *)g_Spfgd.metainfo.arg[1];
    const char **rp = no_route_to;
    const char **rp_end = rp + *no_route_to_nr;
    size_t rp_size = 0;
    int err = EXIT_SUCCESS;
    uint8_t first_addr[16] = { 0 };
    uint8_t last_addr[16] = { 0 };
    int keep_flooding = macgonuts_get_bool_option("keep-flooding", 0);

    while (!g_Spfgd.spoofing.abort && err == EXIT_SUCCESS && rp != rp_end) {
        rp_size = strlen(*rp);
        if (macgonuts_check_ip_addr(*rp, rp_size)) {
            err = macgonuts_get_raw_ip_addr(first_addr, sizeof(first_addr), *rp, rp_size);
            if (err != EXIT_SUCCESS) {
                continue;
            }
            memcpy(&last_addr[0], &first_addr[0], g_Spfgd.layers.proto_addr_size);
        } else {
            err = macgonuts_get_raw_cidr(first_addr, last_addr, *rp, rp_size);
            if (err != EXIT_SUCCESS) {
                continue;
            }
        }
        rp++;
        err = cut_off_route_to(first_addr, last_addr);
        if (keep_flooding && rp == rp_end) {
            rp = no_route_to;
        }
    }

    g_Spfgd.hooks.deinit(&g_Spfgd, NULL, 0);

    if (g_URandomFd != -1) {
        close(g_URandomFd);
        g_URandomFd = -1;
    }

    return err;
}

static int cut_off_route_to(const uint8_t *first_addr, const uint8_t *last_addr) {
    uint8_t curr_addr[16];
    uint8_t stop_addr[16];
    char spoof_addr[100] = "";
    char spoof_mac[32] = "";
    int err = EXIT_FAILURE;

    memcpy(&curr_addr[0], &first_addr[0], g_Spfgd.layers.proto_addr_size);
    memcpy(&stop_addr[0], &last_addr[0], g_Spfgd.layers.proto_addr_size);

    macgonuts_inc_raw_ip(stop_addr, g_Spfgd.layers.proto_addr_size);

    do {
        get_random_mac(&g_Spfgd.layers.spoof_hw_addr[0], sizeof(g_Spfgd.layers.spoof_hw_addr));
        memcpy(&g_Spfgd.layers.spoof_proto_addr[0], &curr_addr[0], g_Spfgd.layers.proto_addr_size);
        macgonuts_inc_raw_ip(curr_addr, g_Spfgd.layers.proto_addr_size);
        err = macgonuts_spoof(g_Spfgd.handles.wire, &g_Spfgd.layers);
        if (err != EXIT_SUCCESS) {
            snprintf(spoof_mac, sizeof(spoof_mac) - 1,
                     "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", g_Spfgd.layers.spoof_proto_addr[0],
                                                      g_Spfgd.layers.spoof_proto_addr[1],
                                                      g_Spfgd.layers.spoof_proto_addr[2],
                                                      g_Spfgd.layers.spoof_proto_addr[3],
                                                      g_Spfgd.layers.spoof_proto_addr[4],
                                                      g_Spfgd.layers.spoof_proto_addr[5]);
            macgonuts_raw_ip2literal(spoof_addr, sizeof(spoof_addr),
                                     g_Spfgd.layers.spoof_proto_addr,
                                     g_Spfgd.layers.proto_addr_size);
            macgonuts_si_error("unable to spoof `%s` as `%s` on `%s`.\n", spoof_addr,
                                                                          spoof_mac,
                                                                          g_Spfgd.usrinfo.tg_address);
            continue;
        }
        err = g_Spfgd.hooks.done(&g_Spfgd, NULL, 0);
        if (err == EXIT_SUCCESS
            && g_Spfgd.spoofing.timeout > 0) {
            usleep(g_Spfgd.spoofing.timeout * 1000);
        }
    } while (!g_Spfgd.spoofing.abort
             && err == EXIT_SUCCESS
             && memcmp(&curr_addr[0], &stop_addr[0], g_Spfgd.layers.proto_addr_size) != 0);

    return err;
}

static void get_random_mac(uint8_t *hw_addr, const size_t hw_addr_size) {
    if (g_URandomFd == -1) {
        g_URandomFd = open("/dev/urandom", O_RDONLY);
        if (g_URandomFd == -1) {
            return;
        }
    }
    memset(hw_addr, 0, hw_addr_size);
    read(g_URandomFd, &hw_addr, hw_addr_size);
}

static int is_valid_no_route_to(const char **no_route_to, const size_t no_route_to_nr) {
    const char **rp = no_route_to;
    const char **rp_end = rp + no_route_to_nr;
    size_t rp_size;

    while (rp != rp_end) {
        rp_size = strlen(*rp);
        if (macgonuts_get_ip_version(*rp, rp_size) != g_Spfgd.layers.proto_addr_size) {
            macgonuts_si_error("ip version mismatch : `%s`.\n", *rp);
            return 0;
        } else if (macgonuts_get_cidr_version(*rp, rp_size) != g_Spfgd.layers.proto_addr_size) {
            macgonuts_si_error("cidr version mismatch : `%s`.\n", *rp);
            return 0;
        }
        rp++;
    }

    return 1;
}

static void sigint_watchdog(int signo) {
    g_Spfgd.spoofing.abort = 1;
}

static int fill_up_lo_info(void) {
    char mac_buf[256] = "";
    int err = macgonuts_get_mac_from_iface(mac_buf, sizeof(mac_buf) - 1, g_Spfgd.usrinfo.lo_iface);
    if (err != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return macgonuts_get_raw_ether_addr(&g_Spfgd.layers.lo_hw_addr[0],
                                        sizeof(g_Spfgd.layers.lo_hw_addr),
                                        mac_buf, sizeof(mac_buf));
}

static int fill_up_tg_info(void) {
    char addr_buf[256] = "";
    size_t tg_address_size = strlen(g_Spfgd.usrinfo.tg_address);
    g_Spfgd.layers.proto_addr_version = macgonuts_get_ip_version(g_Spfgd.usrinfo.tg_address, tg_address_size);
    if (g_Spfgd.layers.proto_addr_version != 4
        && g_Spfgd.layers.proto_addr_version != 6) {
        macgonuts_si_error("you gave me an ip address from outter space, I only support ip version 4 or 6.\n");
        return EXIT_FAILURE;
    }

    g_Spfgd.layers.proto_addr_size = (g_Spfgd.layers.proto_addr_version == 4) ? 4 : 16;

    if (macgonuts_get_addr_from_iface(addr_buf, sizeof(addr_buf) - 1,
                                      g_Spfgd.layers.proto_addr_version,
                                      g_Spfgd.usrinfo.lo_iface) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_raw_ip_addr(g_Spfgd.layers.lo_proto_addr,
                                  g_Spfgd.layers.proto_addr_size,
                                  addr_buf, strlen(addr_buf)) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_raw_ip_addr(g_Spfgd.layers.tg_proto_addr,
                                  g_Spfgd.layers.proto_addr_size,
                                  g_Spfgd.usrinfo.tg_address, tg_address_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_ethaddr(&g_Spfgd.layers.tg_hw_addr[0],
                              sizeof(g_Spfgd.layers.tg_hw_addr),
                              g_Spfgd.usrinfo.tg_address, tg_address_size,
                              g_Spfgd.handles.wire, g_Spfgd.usrinfo.lo_iface) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
