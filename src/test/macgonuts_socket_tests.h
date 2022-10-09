/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_MACGONUTS_SOCKET_TESTS_H
#define MACGONUTS_MACGONUTS_SOCKET_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_create_release_socket_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_sendpkt_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_recvpkt_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_addr_from_iface_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_mac_from_iface_tests);

#endif // MACGONUTS_MACGONUTS_SOCKET_TESTS_H
