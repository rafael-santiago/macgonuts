/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_dnsspoof_done_hook.h>
#include <macgonuts_status_info.h>

int macgonuts_dnsspoof_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                 const unsigned char *ethfrm, const size_t ethfrm_size) {
    // INFO(Rafael): This is hollowed, we only want to detect a redirect and apply some dns poisoning
    //               when convinent, according to users intentions.
    return EXIT_SUCCESS;
}

