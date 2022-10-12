/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ip6mcast_tests.h"
#include <macgonuts_ip6mcast.h>

CUTE_TEST_CASE(macgonuts_get_multicast_addr_tests)
    struct test_ctx {
        char *addr;
        uint8_t mcast[16];
    } test_vector[] = {
        {
            "2001:CAFE::2",
            { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x02 },
        },
        {
            "2001:cafe::3",
            { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x03 },
        },
        {
            "CAFE:FED1:D000::00DE:FECA",
            { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x01, 0xFF, 0xDE, 0xFE, 0xCA }
        },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t mcast[16] = { 0 };
    CUTE_ASSERT(macgonuts_get_multicast_addr(NULL, sizeof(mcast), test->addr, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_multicast_addr(mcast, 0, test->addr, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_multicast_addr(mcast, sizeof(mcast), NULL, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_multicast_addr(mcast, sizeof(mcast), test->addr, 0) == EINVAL);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_multicast_addr(mcast, sizeof(mcast),
                                                 test->addr, strlen(test->addr)) == EXIT_SUCCESS);
        CUTE_ASSERT(memcmp(&mcast[0], &test->mcast[0], sizeof(mcast)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_unsolicited_multicast_addr_tests)
    uint8_t usmcast_addr[16] = { 0 };
    CUTE_ASSERT(macgonuts_get_unsolicited_multicast_addr(NULL, sizeof(usmcast_addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_unsolicited_multicast_addr(usmcast_addr, 17) == EINVAL);
    CUTE_ASSERT(macgonuts_get_unsolicited_multicast_addr(usmcast_addr, sizeof(usmcast_addr)) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(&usmcast_addr[0],
                       "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", sizeof(usmcast_addr)) == 0);
CUTE_TEST_CASE_END
