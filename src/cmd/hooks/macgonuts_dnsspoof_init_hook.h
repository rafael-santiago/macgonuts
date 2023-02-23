/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_HOOKS_MACGONUTS_DNSSPOOF_INIT_HOOK_H
#define MACGONUTS_CMD_HOOKS_MACGONUTS_DNSSPOOF_INIT_HOOK_H 1

#include <macgonuts_types.h>

int macgonuts_dnsspoof_init_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                 const unsigned char *ethfrm, const size_t ethfrm_size);

#endif // MACGONUTS_CMD_HOOKS_MACGONUTS_DNSSPOOF_INIT_HOOK_H
