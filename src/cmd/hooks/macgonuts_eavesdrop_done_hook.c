/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_eavesdrop_done_hook.h>

int macgonuts_eavesdrop_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                  const unsigned char *ethfrm, const size_t ethfrm_size) {
    // INFO(Rafael): Nothing need to be informed to the user, we only want to log packets
    //               when redirecting something. The eavesdrop mode is about active sniffing.
    return EXIT_SUCCESS;
}
