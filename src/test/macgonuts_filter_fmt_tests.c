/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_filter_fmt_tests.h"
#include <macgonuts_filter_fmt.h>

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

CUTE_TEST_CASE(macgonuts_get_filter_glob_ctx_tests)
    struct macgonuts_filter_glob_ctx **filter_globs = NULL;
    size_t filter_globs_nr = 0;
    const char *filters[] = {
        "\xDE\xaD\xBe\xEf",
        "\\xDE\\xaD\\xBe\\xEf",
        "GET /echo HTTP/1.1\r\n",
        "\tTAAAAAB.\\",
        "*[gG][eE][tT]*/test*\r\n",
        "\\xDEADBEEFBEEFDEAD",
        "\\xDEADBEEFBEEFDEAD*tchum!",
    };
    const size_t filters_nr = 7;
    filter_globs = macgonuts_get_filter_glob_ctx(filters, filters_nr, &filter_globs_nr);
    CUTE_ASSERT(filter_globs_nr == 7);
    CUTE_ASSERT(filter_globs != NULL);
    CUTE_ASSERT(filter_globs[0]->glob != NULL);
    CUTE_ASSERT(filter_globs[0]->glob_size == 4);
    CUTE_ASSERT(memcmp(filter_globs[0]->glob, "\xDE\xAD\xBE\xEF", 4) == 0);
    CUTE_ASSERT(filter_globs[1]->glob != NULL);
    CUTE_ASSERT(filter_globs[1]->glob_size == 4);
    CUTE_ASSERT(memcmp(filter_globs[1]->glob, "\xDE\xAD\xBE\xEF", 4) == 0);
    CUTE_ASSERT(filter_globs[2]->glob != NULL);
    CUTE_ASSERT(filter_globs[2]->glob_size == 20);
    CUTE_ASSERT(memcmp(filter_globs[2]->glob, "GET /echo HTTP/1.1\r\n", 20) == 0);
    CUTE_ASSERT(filter_globs[3]->glob != NULL);
    CUTE_ASSERT(filter_globs[3]->glob_size == 10);
    CUTE_ASSERT(memcmp(filter_globs[3]->glob, "\tTAAAAAB.\\", 10) == 0);
    CUTE_ASSERT(filter_globs[4]->glob != NULL);
    CUTE_ASSERT(filter_globs[4]->glob_size == 22);
    CUTE_ASSERT(memcmp(filter_globs[4]->glob, "*[gG][eE][tT]*/test*\r\n", 22) == 0);
    CUTE_ASSERT(filter_globs[5]->glob != NULL);
    CUTE_ASSERT(filter_globs[5]->glob_size == 8);
    CUTE_ASSERT(memcmp(filter_globs[5]->glob, "\xDE\xAD\xBE\xEF\xBE\xEF\xDE\xAD", 8) == 0);
    CUTE_ASSERT(filter_globs[6]->glob != NULL);
    CUTE_ASSERT(filter_globs[6]->glob_size == 15);
    CUTE_ASSERT(memcmp(filter_globs[6]->glob, "\xDE\xAD\xBE\xEF\xBE\xEF\xDE\xAD*tchum!", 15) == 0);
    macgonuts_release_filter_glob_ctx(filter_globs, filter_globs_nr);
CUTE_TEST_CASE_END
