/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_socket_common_tests.h"
#include "macgonuts_test_utils.h"
#include <macgonuts_socket_common.h>

CUTE_TEST_CASE(macgonuts_get_addr_from_iface_unix_tests)
    char expected_addr[1<<10] = "";
    char addr_buf[1<<10] = "";
    get_default_iface_addr(expected_addr);
    CUTE_ASSERT(macgonuts_get_addr_from_iface_unix(NULL, sizeof(addr_buf), 4, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface_unix(addr_buf, 0, 4, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface_unix(addr_buf, sizeof(addr_buf), 7, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface_unix(addr_buf, sizeof(addr_buf), 4, NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface_unix(addr_buf, sizeof(addr_buf), 4,
                                                   get_default_iface_name()) == EXIT_SUCCESS);
    CUTE_ASSERT(strcmp(addr_buf, expected_addr) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_gateway_addr_info_tests)
    uint8_t expected_gw_addr[16] = { 0 };
    char expected_gw_iface[1<<10] = "";
    uint8_t gw_addr[16] = { 0 };
    size_t gw_addr_size = 0;
    char gw_iface[1<<10] = "";
    get_gateway_addr(expected_gw_addr);
    get_gateway_iface(expected_gw_iface);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info(NULL, sizeof(gw_iface), gw_addr, &gw_addr_size) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info(gw_iface, 0, gw_addr, &gw_addr_size) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info(gw_iface, sizeof(gw_iface), NULL, &gw_addr_size) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info(gw_iface, sizeof(gw_iface), gw_addr, NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info(gw_iface, sizeof(gw_iface),
                                                gw_addr, &gw_addr_size) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(gw_addr, expected_gw_addr, gw_addr_size) == 0);
    CUTE_ASSERT(strcmp(gw_iface, expected_gw_iface) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_gateway_hw_addr_tests)
    uint8_t hw_addr[6] = { 0 };
    CUTE_ASSERT(macgonuts_get_gateway_hw_addr(NULL, sizeof(hw_addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_hw_addr(&hw_addr[0], 0) == EINVAL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_maxaddr_from_iface_tests)
    uint8_t netmask[16] = { 0 };
    uint8_t expected[16] = { 0 };
    const char *iface = get_default_iface_name();
    const size_t iface_size = strlen(iface);
    char cmd[1<<10] = "";
    CUTE_ASSERT(macgonuts_get_maxaddr_from_iface(iface, iface_size, netmask, 4) == EXIT_SUCCESS);
    CUTE_ASSERT(get_maxaddr4_from_iface(expected, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(&netmask[0], &expected[0], 4) == 0);
#if defined(__linux__)
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 del dead:beef:0:cafe:fed1::d0/64 >/dev/null 2>&1", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr del dev %s dead:beef:0:cafe:fed1::d0/64 >/dev/null 2>&1", iface);
    }
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 dead:beef:0:cafe:fed1::d0/64 -alias >/dev/null 2>&1", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    system(cmd);
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 add dead:beef:0:cafe:fed1::d0/64", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr add dev %s dead:beef:0:cafe:fed1::d0/64", iface);
    }
    CUTE_ASSERT(system(cmd) == 0);
    CUTE_ASSERT(get_maxaddr6_from_iface(expected, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_get_maxaddr_from_iface(iface, iface_size, netmask, 6) == EXIT_SUCCESS);
#if defined(__linux__)
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 del dead:beef:0:cafe:fed1::d0/64", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr del dev %s dead:beef:0:cafe:fed1::d0/64", iface);
    }
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 dead:beef:0:cafe:fed1::d0/64 -alias", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    CUTE_ASSERT(system(cmd) == 0);
    CUTE_ASSERT(memcmp(&netmask[0], &expected[0], 16) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_netmask_from_iface_tests)
    uint8_t netmask[16] = { 0 };
    uint8_t expected[16] = { 0 };
    char cmd[1<<10] = "";
    const char *iface = get_default_iface_name();
    const size_t iface_size = strlen(iface);
#if defined(__linux__)
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 del dead:beef:0:cafe:fed1::d0/64 >/dev/null 2>&1", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr del dev %s dead:beef:0:cafe:fed1::d0/64 >/dev/null 2>&1", iface);
    }
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 dead:beef:0:cafe:fed1::d0/64 -alias >/dev/null 2>&1", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    system(cmd);
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 add dead:beef:0:cafe:fed1::d0/64", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr add dev %s dead:beef:0:cafe:fed1::d0/64", iface);
    }
    CUTE_ASSERT(system(cmd) == 0);
    CUTE_ASSERT(macgonuts_get_netmask_from_iface(NULL, iface_size, netmask, 4) == EINVAL);
    CUTE_ASSERT(macgonuts_get_netmask_from_iface(iface, 0, netmask, 4) == EINVAL);
    CUTE_ASSERT(macgonuts_get_netmask_from_iface(iface, iface_size, NULL, 4) == EINVAL);
    CUTE_ASSERT(macgonuts_get_netmask_from_iface(iface, iface_size, netmask, 7) == EINVAL);
    CUTE_ASSERT(macgonuts_get_netmask_from_iface(iface, iface_size, netmask, 4) == EXIT_SUCCESS);
    CUTE_ASSERT(get_netmask4_from_iface(expected, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(&netmask[0], &expected[0], 4) == 0);
    CUTE_ASSERT(get_netmask6_from_iface(expected, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_get_netmask_from_iface(iface, iface_size, netmask, 6) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(&netmask[0], &expected[0], 16) == 0);
#if defined(__linux__)
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 del dead:beef:0:cafe:fed1::d0/64", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr del dev %s dead:beef:0:cafe:fed1::d0/64", iface);
    }
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 dead:beef:0:cafe:fed1::d0/64 -alias", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    CUTE_ASSERT(system(cmd) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_gateway_addr_info_from_iface_tests)
    uint8_t addr[16] = { 0 };
    size_t addr_size = 0;
    const char *iface = get_default_iface_name();
    uint8_t expected_addr[16] = { 0 };
    char cmd[1<<10] = "";
    CUTE_ASSERT(macgonuts_get_gateway_addr_info_from_iface(NULL, &addr_size, 4, iface) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info_from_iface(&addr[0], NULL, 4, iface) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 3, iface) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 6, NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 4, iface) == EXIT_SUCCESS);
    get_gateway_addr4_from_iface(expected_addr, iface);
    CUTE_ASSERT(addr_size == 4);
    CUTE_ASSERT(memcmp(&addr[0], &expected_addr, addr_size) == 0);
#if defined(__linux__)
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 del dead:beef:0:cafe:fed1::d0/64 >/dev/null 2>&1", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr del dev %s dead:beef:0:cafe:fed1::d0/64 > /dev/null 2>&1", iface);
    }
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 dead:beef:0:cafe:fed1::d0/64 -alias >/dev/null 2>&1", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    system(cmd);
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 add dead:beef:0:cafe:fed1::d0/64", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr add dev %s dead:beef:0:cafe:fed1::d0/64", iface);
    }
    CUTE_ASSERT(system(cmd) == 0);
    get_gateway_addr6_from_iface(expected_addr, iface);
    CUTE_ASSERT(macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 6, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(addr_size == 16);
    CUTE_ASSERT(memcmp(&addr[0], &expected_addr[0], addr_size) == 0);
#if defined(__linux__)
    if (has_ifconfig()) {
        snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 del dead:beef:0:cafe:fed1::d0/64", iface);
    } else {
        snprintf(cmd, sizeof(cmd) - 1, "ip -6 addr del dev %s dead:beef:0:cafe:fed1::d0/64 > /dev/null 2>&1", iface);
    }
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s inet6 dead:beef:0:cafe:fed1::d0/64 -alias", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    CUTE_ASSERT(system(cmd) == 0);
CUTE_TEST_CASE_END
