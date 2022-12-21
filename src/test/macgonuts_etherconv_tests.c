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
        { "08:00:27:e5:9b:4a", 1 },
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

CUTE_TEST_CASE(macgonuts_get_raw_ip6_mcast_ether_addr_tests)
    struct test_ctx {
        const char *ip6;
        const uint8_t *expected;
    } test_vector[] = {
        { "2001:db08:cafe:Fed1:Dac0::0000:b0b0", (uint8_t *) "\x33\x33\xFF\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0001:b0b0", (uint8_t *) "\x33\x33\xFF\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0002:b0b0", (uint8_t *) "\x33\x33\xFF\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0004:b0b0", (uint8_t *) "\x33\x33\xFF\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0010:b0b0", (uint8_t *) "\x33\x33\xFF\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0020:b0b0", (uint8_t *) "\x33\x33\xFF\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0040:b0b0", (uint8_t *) "\x33\x33\xFF\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0080:b0b0", (uint8_t *) "\x33\x33\xFF\x80\xB0\xB0" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t raw[6] = { 0 };
    CUTE_ASSERT(macgonuts_get_raw_ip6_mcast_ether_addr(NULL, sizeof(raw),
                                                       test->ip6, strlen(test->ip6)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip6_mcast_ether_addr(raw, 0, test->ip6, strlen(test->ip6)) == ERANGE);
    CUTE_ASSERT(macgonuts_get_raw_ip6_mcast_ether_addr(raw, sizeof(raw), NULL, strlen(test->ip6)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip6_mcast_ether_addr(raw, sizeof(raw), test->ip6, 0) == EINVAL);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_raw_ip6_mcast_ether_addr(raw, sizeof(raw),
                                                           test->ip6, strlen(test->ip6)) == EXIT_SUCCESS);
        CUTE_ASSERT(memcmp(raw, test->expected, sizeof(raw)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr_tests)
    struct test_ctx {
        const char *ip6;
        const uint8_t *expected;
    } test_vector[] = {
        // INFO(Rafael): If do not want to test the whole stuff you should not have written it.
        { "2001:db08:cafe:Fed1:Dac0::0000:b0b0", (uint8_t *) "\x33\x33\x00\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0001:b0b0", (uint8_t *) "\x33\x33\x00\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0002:b0b0", (uint8_t *) "\x33\x33\x00\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0004:b0b0", (uint8_t *) "\x33\x33\x00\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0010:b0b0", (uint8_t *) "\x33\x33\x00\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0020:b0b0", (uint8_t *) "\x33\x33\x00\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0040:b0b0", (uint8_t *) "\x33\x33\x00\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0080:b0b0", (uint8_t *) "\x33\x33\x00\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0100:b0b0", (uint8_t *) "\x33\x33\x01\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0101:b0b0", (uint8_t *) "\x33\x33\x01\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0102:b0b0", (uint8_t *) "\x33\x33\x01\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0104:b0b0", (uint8_t *) "\x33\x33\x01\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0110:b0b0", (uint8_t *) "\x33\x33\x01\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0120:b0b0", (uint8_t *) "\x33\x33\x01\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0140:b0b0", (uint8_t *) "\x33\x33\x01\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0180:b0b0", (uint8_t *) "\x33\x33\x01\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0200:b0b0", (uint8_t *) "\x33\x33\x02\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0201:b0b0", (uint8_t *) "\x33\x33\x02\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0202:b0b0", (uint8_t *) "\x33\x33\x02\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0204:b0b0", (uint8_t *) "\x33\x33\x02\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0210:b0b0", (uint8_t *) "\x33\x33\x02\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0220:b0b0", (uint8_t *) "\x33\x33\x02\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0240:b0b0", (uint8_t *) "\x33\x33\x02\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0280:b0b0", (uint8_t *) "\x33\x33\x02\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0400:b0b0", (uint8_t *) "\x33\x33\x04\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0401:b0b0", (uint8_t *) "\x33\x33\x04\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0402:b0b0", (uint8_t *) "\x33\x33\x04\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0404:b0b0", (uint8_t *) "\x33\x33\x04\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0410:b0b0", (uint8_t *) "\x33\x33\x04\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0420:b0b0", (uint8_t *) "\x33\x33\x04\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0440:b0b0", (uint8_t *) "\x33\x33\x04\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0480:b0b0", (uint8_t *) "\x33\x33\x04\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0800:b0b0", (uint8_t *) "\x33\x33\x08\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0801:b0b0", (uint8_t *) "\x33\x33\x08\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0802:b0b0", (uint8_t *) "\x33\x33\x08\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0804:b0b0", (uint8_t *) "\x33\x33\x08\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0810:b0b0", (uint8_t *) "\x33\x33\x08\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0820:b0b0", (uint8_t *) "\x33\x33\x08\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0840:b0b0", (uint8_t *) "\x33\x33\x08\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::0880:b0b0", (uint8_t *) "\x33\x33\x08\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1000:b0b0", (uint8_t *) "\x33\x33\x10\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1001:b0b0", (uint8_t *) "\x33\x33\x10\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1002:b0b0", (uint8_t *) "\x33\x33\x10\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1004:b0b0", (uint8_t *) "\x33\x33\x10\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1010:b0b0", (uint8_t *) "\x33\x33\x10\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1020:b0b0", (uint8_t *) "\x33\x33\x10\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1040:b0b0", (uint8_t *) "\x33\x33\x10\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::1080:b0b0", (uint8_t *) "\x33\x33\x10\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2000:b0b0", (uint8_t *) "\x33\x33\x20\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2001:b0b0", (uint8_t *) "\x33\x33\x20\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2002:b0b0", (uint8_t *) "\x33\x33\x20\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2004:b0b0", (uint8_t *) "\x33\x33\x20\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2010:b0b0", (uint8_t *) "\x33\x33\x20\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2020:b0b0", (uint8_t *) "\x33\x33\x20\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2040:b0b0", (uint8_t *) "\x33\x33\x20\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::2080:b0b0", (uint8_t *) "\x33\x33\x20\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4000:b0b0", (uint8_t *) "\x33\x33\x40\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4001:b0b0", (uint8_t *) "\x33\x33\x40\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4002:b0b0", (uint8_t *) "\x33\x33\x40\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4004:b0b0", (uint8_t *) "\x33\x33\x40\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4010:b0b0", (uint8_t *) "\x33\x33\x40\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4020:b0b0", (uint8_t *) "\x33\x33\x40\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4040:b0b0", (uint8_t *) "\x33\x33\x40\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::4080:b0b0", (uint8_t *) "\x33\x33\x40\x80\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8000:b0b0", (uint8_t *) "\x33\x33\x80\x00\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8001:b0b0", (uint8_t *) "\x33\x33\x80\x01\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8002:b0b0", (uint8_t *) "\x33\x33\x80\x02\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8004:b0b0", (uint8_t *) "\x33\x33\x80\x04\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8010:b0b0", (uint8_t *) "\x33\x33\x80\x10\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8020:b0b0", (uint8_t *) "\x33\x33\x80\x20\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8040:b0b0", (uint8_t *) "\x33\x33\x80\x40\xB0\xB0" },
        { "2001:db08:cafe:Fed1:Dac0::8080:b0b0", (uint8_t *) "\x33\x33\x80\x80\xB0\xB0" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t raw[6] = { 0 };
    CUTE_ASSERT(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr(NULL, sizeof(raw),
                                                                   test->ip6, strlen(test->ip6)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr(raw, 0, test->ip6, strlen(test->ip6)) == ERANGE);
    CUTE_ASSERT(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr(raw, sizeof(raw), NULL, strlen(test->ip6)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr(raw, sizeof(raw), test->ip6, 0) == EINVAL);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr(raw, sizeof(raw),
                                                                       test->ip6, strlen(test->ip6)) == EXIT_SUCCESS);
        CUTE_ASSERT(memcmp(raw, test->expected, sizeof(raw)) == 0);
        test++;
    }
CUTE_TEST_CASE_END
