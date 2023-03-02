/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ROUTECONV_H
#define MACGONUTS_ROUTECONV_H 1

#include <macgonuts_types.h>

int macgonuts_is_outward_dest(const uint8_t *dest_addr, const uint8_t *net_mask,
                              const uint8_t *lo_addr, const size_t addr_size);

#endif // MACGONUTS_ROUTECONV_H
