/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <hooks/macgonuts_spoof_redirect_hook.h>
#include <macgonuts_redirect.h>

int macgonuts_spoof_redirect_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                  const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL && ethfrm != NULL && ethfrm_size > 14);
    return macgonuts_redirect(spfgd->handles.wire, &spfgd->layers, ethfrm, ethfrm_size);
}
