/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_get_ethaddr_tests.h"
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_socket.h>
#include <string.h>

// TODO(Rafael): Mock some macgonuts functions to make this test environment independent.

CUTE_TEST_CASE(macgonuts_get_ethaddr_tests)
    uint8_t hw_addr[6] = { 0 };
    uint8_t expected_hw_addr[6] = { 0x08, 0x00, 0x27, 0x97, 0x64, 0x91 };
    const char *ip = "10.0.2.13";
    macgonuts_socket_t rsk = -1;
    rsk = macgonuts_create_socket("eth1", 1);
    CUTE_ASSERT(rsk != -1);
    CUTE_ASSERT(macgonuts_set_iface_promisc_on("eth1") == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_get_ethaddr(hw_addr, sizeof(hw_addr), ip, strlen(ip), rsk, "eth1") == EXIT_SUCCESS);
    macgonuts_release_socket(rsk);
    CUTE_ASSERT(macgonuts_set_iface_promisc_off("eth1") == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(hw_addr, expected_hw_addr, sizeof(hw_addr)) == 0);
CUTE_TEST_CASE_END
