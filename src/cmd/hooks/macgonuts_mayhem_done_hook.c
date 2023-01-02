/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_mayhem_done_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_mayhem_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                               const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL
           && spfgd->usrinfo.tg_address != NULL
           && spfgd->usrinfo.spoof_address != NULL);

    macgonuts_si_info("`%s` is now unreachable from `%s`.\n", spfgd->usrinfo.spoof_address, spfgd->usrinfo.tg_address);

    return EXIT_SUCCESS;
}
