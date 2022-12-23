/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_TEST_UTILS_H
#define MACGONUTS_TEST_MACGONUTS_TEST_UTILS_H 1

#include <macgonuts_types.h>

const char *get_default_iface_name(void);

void get_default_iface_mac(uint8_t *mac);

void get_default_iface_addr(char *addr);

void get_gateway_addr(uint8_t *addr);

void get_gateway_iface(char *iface);

#endif // MACGONUTS_TEST_MACGONUTS_TEST_UTILS_H
