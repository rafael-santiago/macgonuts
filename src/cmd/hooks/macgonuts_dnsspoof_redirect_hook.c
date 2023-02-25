/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_dnsspoof_redirect_hook.h>
#include <cmd/macgonuts_dnsspoof_defs.h>
#include <macgonuts_dnsspoof.h>

int macgonuts_dnsspoof_redirect_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                     const unsigned char *ethfrm, const size_t ethfrm_size) {
    assert(spfgd != NULL
           && spfgd->handles.wire > -1);
    return macgonuts_dnsspoof(spfgd->handles.wire, &spfgd->layers,
                              macgonuts_dnsspoof_iplist(spfgd),
                              macgonuts_dnsspoof_etc_hoax(spfgd),
                              macgonuts_dnsspoof_ttl(spfgd),
                              ethfrm, ethfrm_size);
}
