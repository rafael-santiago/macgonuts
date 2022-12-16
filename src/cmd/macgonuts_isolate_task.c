/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_isolate_task.h>
#include <cmd/macgonuts_option.h>
#include <macgonuts_status_info.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_socket.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_spoof.h>

static struct macgonuts_spoofing_guidance_ctx g_Spfgd = { 0 };

static int fill_up_lo_info(void);

static int fill_up_tg_info(void);

int macgonuts_isolate_task(void) {
    int err = EFAULT;
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

    g_Spfgd.usrinfo.spoof_address = macgonuts_get_option("no-route-to", NULL);
    if (g_Spfgd.usrinfo.spoof_address == NULL) {
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

macgonuts_isolate_task_epilogue:

    macgonuts_release_spoof_layers_ctx(&g_Spfgd.layers);

    return err;
}

int macgonuts_isolate_task_help(void) {
    macgonuts_si_print("use: macgonuts isolate --lo-iface=<label>\n"
                       "                       --isle-addr=<ip4|ip6>\n"
                       "                       --no-route-to=<(ip4|ip6|cidr4|cidr6)_0>,...,<(ip4|ip6|cidr4|cidr6)_n>\n");
    return EXIT_SUCCESS;
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
