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
