/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_REDIRECT_H
#define MACGONUTS_REDIRECT_H 1

#include <macgonuts_types.h>

int macgonuts_should_redirect(const unsigned char *ethfrm, const size_t ethfrm_size,
                              struct macgonuts_spoof_layers_ctx *spf_layers);

int macgonuts_redirect(const macgonuts_socket_t rsk,
                       struct macgonuts_spoof_layers_ctx *spf_layers,
                       const unsigned char *ethfrm, const size_t ethfrm_size,
                       struct macgonuts_capture_ctx *capture);

#endif // MACGONUTS_REDIRECT_H
