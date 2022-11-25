/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_HOOK_MACGONUTS_SPOOF_DONE_HOOK_H
#define MACGONUTS_HOOK_MACGONUTS_SPOOF_DONE_HOOK_H 1

#include <macgonuts_types.h>

int macgonuts_spoof_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                              const unsigned char *ethfrm, const size_t ethfrm_size);

#endif // MACGONUTS_HOOK_MACGONUTS_SPOOF_DONE_HOOK_H