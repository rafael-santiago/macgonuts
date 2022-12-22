/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_isolate_init_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_isolate_init_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL
            && spfgd->usrinfo.lo_iface != NULL
            && spfgd->usrinfo.tg_address != NULL);

    macgonuts_si_mode_enter_announce("isolate");
    macgonuts_si_print("\n-=-=-=-=-=-=-=-= { you are isolating `%s` } =-=-=-=-=-=-=-=-\n\n", spfgd->usrinfo.tg_address);

    return EXIT_SUCCESS;
}

