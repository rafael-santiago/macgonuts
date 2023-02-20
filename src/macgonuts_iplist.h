/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_IPLIST_H
#define MACGONUTS_IPLIST_H 1

#include <macgonuts_types.h>

typedef struct { } macgonuts_iplist_handle;

macgonuts_iplist_handle *macgonuts_iplist_parse(const char *iplist, const size_t iplist_size);

int macgonuts_iplist_has(macgonuts_iplist_handle *iplist_handle, const uint8_t *in_addr, const size_t in_addr_size);

void macgonuts_iplist_release(macgonuts_iplist_handle *iplist);

#endif // MACGONUTS_IPLIST_H
