/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_DNSCONV_H
#define MACGONUTS_DNSCONV_H 1

#include <macgonuts_types.h>

uint8_t *macgonuts_get_dns_u8str(const unsigned char *data, const size_t data_size,
                                 size_t *u8str_size, const size_t current_offset);

#endif // MACGONUTS_DNSCONV_H
