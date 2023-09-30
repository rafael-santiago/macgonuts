/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ETC_HOAX_H
#define MACGONUTS_ETC_HOAX_H 1

#include <macgonuts_types.h>

typedef struct { } macgonuts_etc_hoax_handle;

macgonuts_etc_hoax_handle *macgonuts_open_etc_hoax(const char *filepath);

void macgonuts_close_etc_hoax(macgonuts_etc_hoax_handle *etc_hoax);

int macgonuts_gethoaxbyname(uint8_t *in_addr, const size_t in_addr_max_size, size_t *in_addr_size,
                            macgonuts_etc_hoax_handle *etc_hoax, const char *name, const size_t name_size);

#endif // MACGONUTS_ETC_HOAX_H
