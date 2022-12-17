/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_isolate_done_hook.h>
#include <macgonuts_status_info.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ipconv.h>

int macgonuts_isolate_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                const unsigned char *ethfrm, const size_t ethfrm_size) {
    char spoof_mac[256] = "";
    char spoof_address[256] = "";

    assert(spfgd != NULL
           && spfgd->usrinfo.lo_iface != NULL
           && spfgd->usrinfo.tg_address != NULL
           && spfgd->usrinfo.spoof_address != NULL);
    snprintf(spoof_mac, sizeof(spoof_mac) - 1, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", spfgd->layers.spoof_hw_addr[0],
                                                                                spfgd->layers.spoof_hw_addr[1],
                                                                                spfgd->layers.spoof_hw_addr[2],
                                                                                spfgd->layers.spoof_hw_addr[3],
                                                                                spfgd->layers.spoof_hw_addr[4],
                                                                                spfgd->layers.spoof_hw_addr[5]);
    macgonuts_si_info("fuddling resolution info (`%s` == `%s`) sent to `%s`...\n", spoof_mac, spoof_address,
                                                                                   spfgd->usrinfo.tg_address);
    return EXIT_SUCCESS;
}

