/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_etherconv_tests.h"
#include <macgonuts_etherconv.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_check_ether_addr_tests)
    struct test_ctx {
        const char *mac;
        const int valid;
    } test_vector[] = {
        { "00:DE:AD:BE:EF:00", 1 },
        { "0:DE:AD:BE:EF:00", 0 },
        { "DE:AD:BE:EF:00", 0 },
        { "AD:BE:EF:00", 0 },
        { "BE:EF:00", 0 },
        { "EF:00", 0 },
        { "00", 0 },
        { "00:de:ad:be:ef:00", 1 },
        { "0:de:ad:be:ef:00", 0 },
        { "de:ad:be:ef:00", 0 },
        { "ad:be:ef:00", 0 },
        { "be:ef:00", 0 },
        { "ef:00", 0 },
        { "mean greeens", 0 },
        { "AA:BB:CC:DD:EE:FF", 1 },
        { "BB:CC:DD:EE:FF:GG", 0 },
        { "aa:bb:cc:dd:ee:ff", 1 },
        { "bb:cc:dd:ee:ff:gg", 0 },
        { "aA:bB:cC:dD:eE:fF", 1 },
        { "bB:cC:dD:eE:fF:gG", 0 },
        { "Aa:Bb:Cc:Dd:Ee:Ff", 1 },
        { "Bb:Cc:Dd:Ee:Ff:Gg", 0 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_check_ether_addr(test->mac, strlen(test->mac)) == test->valid);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_getrandom_ether_addr_tests)
    size_t c = 10;
    char eth_addr[18] = { 0 };
    for (c = 0; c < 18; c++) {
        CUTE_ASSERT(macgonuts_getrandom_ether_addr(eth_addr, c) == EXIT_FAILURE);
    }
    while (c-- > 0) {
        CUTE_ASSERT(macgonuts_getrandom_ether_addr(eth_addr, sizeof(eth_addr)) == EXIT_SUCCESS);
        CUTE_ASSERT(macgonuts_check_ether_addr(eth_addr, strlen(eth_addr)) == 1);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_raw_ether_addr_tests)
    struct test_ctx {
        const char *addr;
        const uint8_t *expected;
    } test_vector[] = {
        { "01:02:03:04:05:06", (uint8_t *)"\x01\x02\x03\x04\x05\x06" },
        { "ca:fe:fe:d1:da:c0", (uint8_t *)"\xCA\xFE\xFE\xD1\xDA\xC0" },
        { "08:00:27:9e:fe:d9", (uint8_t *)"\x08\x00\x27\x9E\xFE\xD9" },
        { "08:00:27:e5:9b:4a", (uint8_t *)"\x08\x00\x27\xE5\x9B\x4A" },
        { "08:00:27:9E:FE:D9", (uint8_t *)"\x08\x00\x27\x9E\xFE\xD9" },
        { "08:00:27:E5:9B:4A", (uint8_t *)"\x08\x00\x27\xE5\x9B\x4A" },
        { "CA:FE:FE:D1:DA:C0", (uint8_t *)"\xCA\xFE\xFE\xD1\xDA\xC0" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t raw[6] = { 0 };
    CUTE_ASSERT(macgonuts_get_raw_ether_addr(NULL, sizeof(raw), test->addr, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ether_addr(raw, 0, test->addr, strlen(test->addr)) == ERANGE);
    CUTE_ASSERT(macgonuts_get_raw_ether_addr(raw, sizeof(raw), NULL, 10) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ether_addr(raw, sizeof(raw), test->addr, 0) == EINVAL);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_raw_ether_addr(raw, sizeof(raw), test->addr, strlen(test->addr)) == EXIT_SUCCESS);
        CUTE_ASSERT(memcmp(raw, test->expected, sizeof(raw)) == 0);
        test++;
    }
CUTE_TEST_CASE_END
