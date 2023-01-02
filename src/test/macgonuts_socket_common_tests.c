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
