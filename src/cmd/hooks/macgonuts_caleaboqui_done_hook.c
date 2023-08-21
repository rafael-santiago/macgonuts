/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_caleaboqui_done_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_caleaboqui_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                   const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd->usrinfo.tg_address != NULL);
    macgonuts_si_info("internet access from `%s` was cut off.\n", spfgd->usrinfo.tg_address);
    return EXIT_SUCCESS;
}
