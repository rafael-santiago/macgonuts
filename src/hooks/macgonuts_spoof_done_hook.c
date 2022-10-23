/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <hooks/macgonuts_spoof_done_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_spoof_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                              const void *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL
           && spfgd->usrinfo.tg_address != NULL
           && spfgd->usrinfo.lo_mac_address != NULL
           && spfgd->usrinfo.spoof_mac_address);

    macgonuts_si_info("a spoofed %s packet was sent to `%s`, it shall override `%s` with `%s` on `%s`.\n",
                      ((spfgd->layers.proto_addr_version == 4) ? "ARP" : "NDP"),
                      spfgd->usrinfo.tg_address,
                      spfgd->usrinfo.spoof_mac_address,
                      spfgd->usrinfo.lo_mac_address,
                      spfgd->usrinfo.tg_address);

    return EXIT_SUCCESS;
}
