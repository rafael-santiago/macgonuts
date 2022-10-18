/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_SPOOF_H
#define MACGONUTS_SPOOF_H 1

#include <macgonuts_types.h>

int macgonuts_spoof(const macgonuts_socket_t rsk,
                    struct macgonuts_spoof_on_layers_ctx *spf_layers);

void macgonuts_release_spoof_on_layers_ctx(struct macgonuts_spoof_on_layers_ctx *spf_layers);

#endif // MACGONUTS_SPOOF_H
