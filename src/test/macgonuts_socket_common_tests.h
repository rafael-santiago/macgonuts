/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_SOCKET_COMMON_TESTS_H
#define MACGONUTS_TEST_MACGONUTS_SOCKET_COMMON_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_get_addr_from_iface_unix_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_gateway_addr_info_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_gateway_hw_addr_tests);

//CUTE_DECLARE_TEST_CASE(macgonuts_get_maxaddr_from_iface_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_netmask_from_iface_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_gateway_addr_info_from_iface_tests);

#endif // MACGONUTS_TEST_MACGONUTS_SOCKET_COMMON_TESTS_H
