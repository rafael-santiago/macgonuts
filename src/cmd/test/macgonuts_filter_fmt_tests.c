/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_filter_fmt_tests.h"
#include <cmd/macgonuts_filter_fmt.h>

CUTE_TEST_CASE(macgonuts_format_filter_tests)
    struct test_ctx {
        const char *filter_str;
        const size_t filter_size;
        const unsigned char *expected_fmt_filter;
        const size_t expected_fmt_filter_size;
    } test_vector[] = {
        { "\xDE\xaD\xBe\xEf", 4, (unsigned char *)"\xDE\xAD\xBE\xEF", 4 },
        { "\\xDE\\xaD\\xBe\\xEf", 16, (unsigned char *)"\xDE\xAD\xBE\xEF", 4 },
        { "GET /echo HTTP/1.1\r\n", 20, (unsigned char *)"GET /echo HTTP/1.1\r\n", 20 },
        { "\tTAAAAAB.\\", 11, (unsigned char *)"\tTAAAAAB.\\", 10 },
        { "\xDE ADBEEFBEEFDEAD", 16, (unsigned char *)"\xDE ADBEEFBEEFDEAD", 16 },
        { "*[gG][eE][tT]*/test*\r\n", 22, (unsigned char *)"*[gG][eE][tT]*/test*\r\n", 22 },
        { "\\xDEADBEEFBEEFDEAD", 18, (unsigned char *)"\xDE\xAD\xBE\xEF\xBE\xEF\xDE\xAD", 8 },
        { "\\xDEADBEEFBEEFDEAD*tchum!", 18, (unsigned char *)"\xDE\xAD\xBE\xEF\xBE\xEF\xDE\xAD*tchum!", 15 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    unsigned char *filter = NULL;
    size_t filter_size = 0;
    while (test != test_end) {
        filter = macgonuts_format_filter(test->filter_str, strlen(test->filter_str), &filter_size);
        CUTE_ASSERT(filter_size == test->expected_fmt_filter_size);
        CUTE_ASSERT(memcmp(filter, test->expected_fmt_filter, filter_size) == 0);
        free(filter);
        test++;
    }
CUTE_TEST_CASE_END
