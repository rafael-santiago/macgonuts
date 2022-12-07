/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_eavesdrop_init_hook.h>
#include <macgonuts_status_info.h>
#include <macgonuts_ipconv.h>

int macgonuts_eavesdrop_init_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                  const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL
            && spfgd->usrinfo.lo_iface != NULL
            && spfgd->usrinfo.tg_address != NULL
            && spfgd->usrinfo.spoof_address != NULL);

    macgonuts_si_mode_enter_announce("eavesdrop");

    macgonuts_si_print(">>> Capturing all communication between %s and %s [nic %s] <<<\n\n", spfgd->usrinfo.tg_address,
                                                                                             spfgd->usrinfo.spoof_address,
                                                                                             spfgd->usrinfo.lo_iface);
    if (spfgd->metainfo.arg[0] != NULL) {
        macgonuts_si_info("dumping all captured data to `%s`.\n", spfgd->metainfo.arg[0]);
    }

    macgonuts_si_info("hit Ctrl + C to exit.\n");

    return EXIT_SUCCESS;
}

