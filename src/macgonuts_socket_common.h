/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_MACGONUTS_SOCKET_COMMON_H
#define MACGONUTS_MACGONUTS_SOCKET_COMMON_H 1

#include <macgonuts_types.h>

// TIP(Rafael): If you define this function weak here instead of into `macgonuts_socket.h` it will not work
//              on production because linker will not find this symbol in `macgonuts_socket.o`. The rule of thumb
//              to avoid weak definitions headaches is: define the weak implementations into one single object,
//              i.e. into one implementation file.

int macgonuts_get_addr_from_iface_unix(char *addr_buf, const size_t max_addr_buf_size,
                                       const int addr_version, const char *iface);

extern int macgonuts_get_gateway_addr_info(char *iface_buf, const size_t iface_buf_size,
                                           uint8_t *raw, size_t *raw_size);

int macgonuts_get_gateway_addr_info_from_iface(uint8_t *raw, size_t *raw_size, const int ip_version, const char *iface);

int macgonuts_get_gateway_hw_addr(uint8_t *hw_addr, const size_t hw_addr_size);

int macgonuts_get_maxaddr_from_iface(const char *iface_buf,
                                     const size_t iface_buf_size,
                                     uint8_t *raw, const int ip_version);

int macgonuts_get_netmask_from_iface(const char *iface_buf, const size_t iface_buf_size,
                                     uint8_t *raw, const int ip_version);

#endif // MACGONUTS_MACGONUTS_SOCKET_COMMON_H
