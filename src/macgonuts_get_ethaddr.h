/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_GET_ETHADDR_H
#define MACGONUTS_GET_ETHADDR_H 1

#include <macgonuts_types.h>

int macgonuts_get_ethaddr(uint8_t *hw_addr, const size_t hw_addr_size,
                          const char *layer3addr, const size_t layer3addr_size,
                          macgonuts_socket_t rsk, const char *iface);


#endif // MACGONUTS_GET_ETHADDR_H

