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
                              const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL);

    macgonuts_si_info("%s -> `%s`, MAC `%s` will override `%s` at `%s`.\n",
                      ((spfgd->layers.proto_addr_version == 4) ? "ARP reply" : "Neighbor advertisement"),
                      spfgd->usrinfo.tg_address,
                      spfgd->usrinfo.lo_mac_address,
                      spfgd->usrinfo.spoof_mac_address,
                      spfgd->usrinfo.tg_address);

    return EXIT_SUCCESS;
}
