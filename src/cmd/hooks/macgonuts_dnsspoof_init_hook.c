/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_dnsspoof_init_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_dnsspoof_init_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                 const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL
           && spfgd->usrinfo.lo_iface != NULL
           && spfgd->usrinfo.tg_address != NULL
           && spfgd->usrinfo.spoof_address != NULL);

    macgonuts_si_mode_enter_announce("dnsspoof");

    macgonuts_si_print(">>> Monitoring any DNS request with `%s` (looking for pkts to `%s`).\n", spfgd->usrinfo.lo_iface,
                                                                                           spfgd->usrinfo.spoof_address);

    macgonuts_si_info("hit Ctrl + C to exit.\n\n");

    return EXIT_SUCCESS;
}

