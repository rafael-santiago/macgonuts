/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <hooks/macgonuts_spoof_init_hook.h>
#include <macgonuts_status_info.h>
//#include <macgonuts_ipconv.h>
//#include <macgonuts_etherconv.h>

int macgonuts_spoof_init_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                              const unsigned char *ethfrm, const size_t ethfrm_size) {
    char info[8<<10] = "";

    assert(spfgd != NULL
           && spfgd->usrinfo.lo_iface != NULL
           && spfgd->usrinfo.tg_address != NULL
           && spfgd->usrinfo.spoof_address != NULL);

    snprintf(spfgd->usrinfo.lo_mac_address, sizeof(spfgd->usrinfo.lo_mac_address),
             "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", spfgd->layers.lo_hw_addr[0],
                                              spfgd->layers.lo_hw_addr[1],
                                              spfgd->layers.lo_hw_addr[2],
                                              spfgd->layers.lo_hw_addr[3],
                                              spfgd->layers.lo_hw_addr[4],
                                              spfgd->layers.lo_hw_addr[5]);

    snprintf(spfgd->usrinfo.tg_mac_address, sizeof(spfgd->usrinfo.tg_mac_address),
             "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", spfgd->layers.tg_hw_addr[0],
                                              spfgd->layers.tg_hw_addr[1],
                                              spfgd->layers.tg_hw_addr[2],
                                              spfgd->layers.tg_hw_addr[3],
                                              spfgd->layers.tg_hw_addr[4],
                                              spfgd->layers.tg_hw_addr[5]);

    snprintf(spfgd->usrinfo.spoof_mac_address, sizeof(spfgd->usrinfo.spoof_mac_address),
             "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", spfgd->layers.spoof_hw_addr[0],
                                              spfgd->layers.spoof_hw_addr[1],
                                              spfgd->layers.spoof_hw_addr[2],
                                              spfgd->layers.spoof_hw_addr[3],
                                              spfgd->layers.spoof_hw_addr[4],
                                              spfgd->layers.spoof_hw_addr[5]);

    macgonuts_si_mode_enter_announce("spoof");

    snprintf(info, sizeof(info) - 1,
             ">>> Spoofing context\n"
             "\t* local interface [ %20s ]\n"
             "\t* target ip       [ %20s ]\n"
             "\t* spoofed ip      [ %20s ]\n"
             "\t* local mac       [ %20s ]\n"
             "\t* target mac      [ %20s ]\n"
             "\t* spoofed mac     [ %20s ]\n"
             "\t* spoof type      [ %20s ]\n"
             "<<<\n", spfgd->usrinfo.lo_iface,
                    spfgd->usrinfo.tg_address,
                    spfgd->usrinfo.spoof_address,
                    spfgd->usrinfo.lo_mac_address,
                    spfgd->usrinfo.tg_mac_address,
                    spfgd->usrinfo.spoof_mac_address,
                    ((spfgd->layers.proto_addr_version == 4) ? "ARP" : "NDP"));

    macgonuts_si_print("%s", info);
    macgonuts_si_info("hit Ctrl + C to exit.\n");

    return EXIT_SUCCESS;
}
