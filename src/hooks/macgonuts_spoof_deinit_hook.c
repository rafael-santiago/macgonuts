/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <hooks/macgonuts_spoof_deinit_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_spoof_deinit_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                const void *ethfrm, const size_t ethfrm_size) {
    macgonuts_si_mode_leave_announce("spoof");
    return EXIT_SUCCESS;
}


