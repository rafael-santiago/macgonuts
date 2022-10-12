/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ETHERCONV_H
#define MACGONUTS_ETHERCONV_H 1

#include <macgonuts_types.h>

int macgonuts_check_ether_addr(const char *ether, const size_t ether_size);

int macgonuts_getrandom_ether_addr(char *ether, const size_t max_ether_size);

int macgonuts_get_raw_ether_addr(uint8_t *raw, const size_t max_raw_size,
                                 const char *ether_addr, const size_t ether_addr_size);

int macgonuts_get_raw_ip6_mcast_ether_addr(uint8_t *raw, const size_t max_raw_size,
                                           const char *ip6_addr, const size_t ip6_addr_size);

int macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr(uint8_t *raw, const size_t max_raw_size,
                                                       const char *ip6_addr, const size_t ether_addr_size);

#endif // MACGONUTS_ETHERCONV_H

