/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ipchsum_tests.h"
#include <macgonuts_ipchsum.h>

CUTE_TEST_CASE(macgonuts_eval_ipchsum_tests)
    struct test_ctx {
        const unsigned char *data;
        const size_t data_size;
        const unsigned char *pseudo_header;
        const size_t pseudo_header_size;
        const uint16_t expected;
    } test_vector[] = {
        {
            (const unsigned char *)"\x45\x00\x00\x3C\x1C\x46\x40\x00\x40\x06"
                                   "\x00\x00\xAC\x10\x0A\x63\xAC\x10\x0A\x0C", 20,
            NULL, 0,
            0xB1E6
        },
        {
            (const unsigned char *)"\x87\x00\x00\x00\x00\x00"
                                   "\x00\x00\x20\x01\xCA\xFE"
                                   "\x00\x00\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00\x00\x03"
                                   "\x01\x01\x08\x00\x27\x5D"
                                   "\x5B\xB8", 32,
            (const unsigned char *)"\x20\x01\xCA\xFE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                                   "\xFF\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xFF\x00\x00\x03"
                                   "\x00\x00\x00\x20\x00\x00\x00\x3A", // INFO(Rafael): IP6 pseudo-header.
            40,
            0x1882
        }
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    CUTE_ASSERT(macgonuts_eval_ipchsum(NULL, 20, NULL, 0) == 0);
    CUTE_ASSERT(macgonuts_eval_ipchsum(test, 0, NULL, 0) == 0);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_eval_ipchsum(test->data, test->data_size,
                                           test->pseudo_header, test->pseudo_header_size) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END
