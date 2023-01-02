/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_mayhem_init_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_mayhem_init_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                               const unsigned char *ethfrm, const size_t ethfrm_size) {
    macgonuts_si_mode_enter_announce("mayhem");
    return EXIT_SUCCESS;
}
