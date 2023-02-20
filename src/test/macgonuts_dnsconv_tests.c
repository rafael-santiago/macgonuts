/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_dnsconv_tests.h"
#include <macgonuts_dnsconv.h>

CUTE_TEST_CASE(macgonuts_get_dns_u8str_tests)
    // INFO(Rafael): Extracted from RFC-1035, 30 pp.
    const unsigned char test_data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

                                        0x01, 0x46,
                                        0x03, 0x49, 0x53, 0x49,
                                        0x04, 0x41, 0x52, 0x50, 0x41,
                                        0x00,

                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

                                        0x03, 0x46, 0x4F, 0x4F,
                                        0xC0, 0x14,

                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

                                        0xC0, 0x1A,

                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

                                        0x00 };
    const size_t test_data_size = sizeof(test_data) / sizeof(test_data[0]);
    struct test_ctx {
        const unsigned char *data;
        const size_t data_size;
        size_t c_off;
        int is_domain_name;
        const uint8_t *expected;
        const size_t expected_size;
    } test_vector[] = {
        { NULL, test_data_size, 20, 0, NULL, 0 },
        { test_data, 0, 20, 1, NULL, 0 },
        { test_data, test_data_size, test_data_size << 1, 0, NULL, 0 },
        { test_data, test_data_size, 20, 1, (uint8_t *)"F.ISI.ARPA", 10 },
        { test_data, test_data_size, 40, 1, (uint8_t *)"FOO.F.ISI.ARPA", 14 },
        { test_data, test_data_size, 64, 1, (uint8_t *)"ARPA", 4 },
        { test_data, test_data_size, 92, 1, NULL, 0 },
        { test_data, test_data_size, 20, 0, (uint8_t *)"FISIARPA", 8 },
        { test_data, test_data_size, 40, 0, (uint8_t *)"FOOFISIARPA", 11 },
        { test_data, test_data_size, 64, 0, (uint8_t *)"ARPA", 4 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t *u8str = NULL;
    size_t u8str_size = 0;
    CUTE_ASSERT(macgonuts_get_dns_u8str(test->data, test->data_size, NULL, test->c_off, test->is_domain_name) == NULL);
    while (test != test_end) {
        u8str = macgonuts_get_dns_u8str(test->data, test->data_size, &u8str_size, test->c_off, test->is_domain_name);
        if (test->expected != NULL) {
            CUTE_ASSERT(u8str != NULL);
            CUTE_ASSERT(u8str_size == test->expected_size);
            CUTE_ASSERT(memcmp(test->expected, u8str, u8str_size) == 0);
            free(u8str);
        } else {
            CUTE_ASSERT(u8str == NULL);
            CUTE_ASSERT(u8str_size == 0);
        }
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_qname_size_from_dname_tests)
    struct test_ctx {
        const uint8_t *data;
        const size_t expected_size;
    } test_vector[] = {
        { "www.qotsa.com", 14 },
        { "www.queensofthestoneage.com", 28 },
        { "www.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", 264 },
        { "www.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", 0 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_qname_size_from_dname(test->data, strlen(test->data)) == test->expected_size);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_label_from_domain_name_tests)
    struct test_ctx {
        const uint8_t *domain_name;
        const size_t domain_name_size;
        const uint8_t *expected;
    } test_vector[] = {
        { "www.ethics.edu", 14, (uint8_t *)"\x03www\x06\x65thics\x03\x65\x64u" },
        { "www.qotsa.com", 13, (uint8_t *)"\x03www\x05qotsa\x03\x63om" },
        { "www.music.com", 13, (uint8_t *)"\x03www\x05music\x03\x63om" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t *label = NULL;
    size_t label_size = 0;
    CUTE_ASSERT(macgonuts_make_label_from_domain_name(NULL, test->domain_name_size, &label_size) == NULL);
    CUTE_ASSERT(macgonuts_make_label_from_domain_name(test->domain_name, 0, &label_size) == NULL);
    CUTE_ASSERT(macgonuts_make_label_from_domain_name(test->domain_name, test->domain_name_size, NULL) == NULL);
    while (test != test_end) {
        label = macgonuts_make_label_from_domain_name(test->domain_name, test->domain_name_size, &label_size);
        CUTE_ASSERT(label != NULL);
        CUTE_ASSERT(label_size == test->domain_name_size + 1);
        CUTE_ASSERT(memcmp(label, test->expected, test->domain_name_size + 1) == 0);
        free(label);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_is_dnsreq_tests)
    const unsigned char dns4[] = {
        // INFO(Rafael): Ethernet frame.
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
        0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0x0A, 0x00, 0x02, 0x0F,
        0xC0, 0xA8, 0x05, 0x01,
        // INFO(Rafael): UDP datagram (DNS).
        0x9F, 0xC3, 0x00, 0x35,
        0x00, 0x24, 0xD1, 0xED,
        0x35, 0x8F, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6F, 0x6F,
        0x67, 0x6C, 0x65, 0x03,
        0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x1C, 0x00, 0x01
    };
    const size_t dns4_size = sizeof(dns4) / sizeof(dns4[0]);
    const unsigned char dns6[] = {
        // INFO(Rafael): Ethernet frame.
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
        0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x20,
        0x11, 0xFF, 0x20, 0x01, 0xCA, 0xFE,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xFF, 0x00, 0x00, 0x03,
        // INFO(Rafael): UDP datagram (DNS).
        0x9F, 0xC3, 0x00, 0x35,
        0x00, 0x24, 0xD1, 0xED,
        0x35, 0x8F, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6F, 0x6F,
        0x67, 0x6C, 0x65, 0x03,
        0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x1C, 0x00, 0x01
    };
    const size_t dns6_size = sizeof(dns6) / sizeof(dns6[0]);
    const unsigned char non_dns4[] = {
        // INFO(Rafael): Ethernet frame.
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
        0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0x0A, 0x00, 0x02, 0x0F,
        0xC0, 0xA8, 0x05, 0x01,
        // INFO(Rafael): UDP datagram (DNS).
        0x9F, 0xC3, 0x00, 0x36,
        0x00, 0x24, 0xD1, 0xED,
        0x35, 0x8F, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6F, 0x6F,
        0x67, 0x6C, 0x65, 0x03,
        0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x1C, 0x00, 0x01
    };
    const size_t non_dns4_size = sizeof(non_dns4) / sizeof(non_dns4[0]);
    const unsigned char non_dns6[] = {
        // INFO(Rafael): Ethernet frame.
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
        0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x20,
        0x11, 0xFF, 0x20, 0x01, 0xCA, 0xFE,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xFF, 0x00, 0x00, 0x03,
        // INFO(Rafael): UDP datagram (DNS).
        0x9F, 0xC3, 0x00, 0x50,
        0x00, 0x24, 0xD1, 0xED,
        0x35, 0x8F, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6F, 0x6F,
        0x67, 0x6C, 0x65, 0x03,
        0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x1C, 0x00, 0x01
    };
    const size_t non_dns6_size = sizeof(non_dns6) / sizeof(non_dns6[0]);
    const unsigned char ethfrm[] = {
        // INFO(Rafael): Ethernet frame.
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
        0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
        0x86, 0xDD,
    };
    const size_t ethfrm_size = sizeof(ethfrm) / sizeof(ethfrm[0]);
    CUTE_ASSERT(macgonuts_is_dnsreq(NULL, dns4_size) == 0);
    CUTE_ASSERT(macgonuts_is_dnsreq(dns4, 0) == 0);
    CUTE_ASSERT(macgonuts_is_dnsreq(dns4, dns4_size) == 1);
    CUTE_ASSERT(macgonuts_is_dnsreq(dns6, dns6_size) == 1);
    CUTE_ASSERT(macgonuts_is_dnsreq(non_dns4, non_dns4_size) == 0);
    CUTE_ASSERT(macgonuts_is_dnsreq(non_dns6, non_dns6_size) == 0);
    CUTE_ASSERT(macgonuts_is_dnsreq(ethfrm, ethfrm_size) == 0);
CUTE_TEST_CASE_END
