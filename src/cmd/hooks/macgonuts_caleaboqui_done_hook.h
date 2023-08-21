/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_CALEABOQUI_DONE_HOOK_H
#define MACGONUTS_CMD_MACGONUTS_CALEABOQUI_DONE_HOOK_H 1

#include <macgonuts_types.h>

int macgonuts_caleaboqui_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                   const unsigned char *ethfrm, const size_t ethfrm_size);

#endif // MACGONUTS_CMD_MACGONUTS_CALEABOQUI_DONE_HOOK_H
