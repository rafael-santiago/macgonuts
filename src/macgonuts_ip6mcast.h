/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_IP6MCAST_H
#define MACGONUTS_IP6MCAST_H 1

#include <macgonuts_types.h>

int macgonuts_get_multicast_addr(uint8_t *mcast, const size_t mcast_size,
                                 const char *ip6, const size_t ip6_size);

int macgonuts_get_unsolicited_multicast_addr(uint8_t *mcast, const size_t mcast_size);

#endif
