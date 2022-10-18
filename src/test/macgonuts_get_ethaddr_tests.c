/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_get_ethaddr_tests.h"
#include "macgonuts_mocks.h"
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_socket.h>
#include <string.h>
#include <stdio.h>

static uint8_t g_FullARPReply[] = {
    0x08, 0x00, 0x27, 0xE5,
    0x9B, 0x4A, 0x08, 0x00,
    0x27, 0x97, 0x64, 0x91,
    0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04,
    0x00, 0x02, 0x08, 0x00,
    0x27, 0x97, 0x64, 0x91,
    0x0A, 0x00, 0x02, 0x0D,
    0x08, 0x00, 0x27, 0xE5,
    0x9B, 0x4A, 0x0A, 0x00,
    0x02, 0x0B, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static uint8_t g_FullNDPNAReply[] = {
    0x08, 0x00, 0x27, 0xE5,
    0x9B, 0x4A, 0x08, 0x00,
    0x27, 0x97, 0x64, 0x91,
    0x86, 0xDD, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x20,
    0x3A, 0xFF, 0x20, 0x01,
    0x0D, 0xB8, 0x00, 0x00,
    0xF1, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x20, 0x01,
    0x0D, 0xB8, 0x00, 0x00,
    0xF1, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x88, 0x00,
    0x25, 0x42, 0x60, 0x00,
    0x00, 0x00, 0x20, 0x01,
    0x0D, 0xB8, 0x00, 0x00,
    0xF1, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x02, 0x01,
    0x08, 0x00, 0x27, 0x97,
    0x64, 0x91
};

CUTE_TEST_CASE(macgonuts_get_ethaddr_ip4_tests)
    uint8_t hw_addr[6] = { 0 };
    uint8_t expected_hw_addr[6] = { 0x08, 0x00, 0x27, 0x97, 0x64, 0x91 };
    const char *ip = "10.0.2.13";
    macgonuts_socket_t rsk = -1;
    mock_set_expected_ip_version(4);
    mock_set_expected_ip4_addr("10.0.2.11");
    mock_set_recv_buf(g_FullARPReply, sizeof(g_FullARPReply));
    rsk = macgonuts_create_socket("eth1", 1);
    CUTE_ASSERT(rsk != -1);
    CUTE_ASSERT(macgonuts_set_iface_promisc_on("eth1") == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_get_ethaddr(hw_addr, sizeof(hw_addr), ip, strlen(ip), rsk, "eth1") == EXIT_SUCCESS);
    macgonuts_release_socket(rsk);
    CUTE_ASSERT(macgonuts_set_iface_promisc_off("eth1") == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(hw_addr, expected_hw_addr, sizeof(hw_addr)) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_ethaddr_ip6_tests)
    uint8_t hw_addr[6] = { 0 };
    uint8_t expected_hw_addr[6] = { 0x08, 0x00, 0x27, 0x97, 0x64, 0x91 };
    const char *ip = "2001:db8:0:f101::3";
    macgonuts_socket_t rsk = -1;
    mock_set_expected_ip_version(6);
    mock_set_expected_ip6_addr("2001:db8:0:f101::2");
    mock_set_recv_buf(g_FullNDPNAReply, sizeof(g_FullNDPNAReply));
    rsk = macgonuts_create_socket("eth1", 1);
    CUTE_ASSERT(rsk != -1);
    CUTE_ASSERT(macgonuts_set_iface_promisc_on("eth1") == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_get_ethaddr(hw_addr, sizeof(hw_addr), ip, strlen(ip), rsk, "eth1") == EXIT_SUCCESS);
    macgonuts_release_socket(rsk);
    CUTE_ASSERT(macgonuts_set_iface_promisc_off("eth1") == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(hw_addr, expected_hw_addr, sizeof(hw_addr)) == 0);
CUTE_TEST_CASE_END

