/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_memglob_tests.h"
#include <macgonuts_memglob.h>

CUTE_TEST_CASE(macgonuts_memglob_tests)
    struct strglob_tests_ctx {
        const unsigned char *data;
        const size_t data_size;
        const unsigned char *pattern;
        const size_t pattern_size;
        int result;
    };
    struct strglob_tests_ctx tests[] = {
        { NULL, 0, NULL, 0, 0 },
        { "abc", 3, "abc", 3, 1 },
        { "abc", 3, "ab", 2, 0 },
        { "abc", 3, "a?c", 3, 1 },
        { "abc", 3, "ab[abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.c]", 57, 1 },
        { "abc", 3, "ab[abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.?]", 57, 0 },
        { "ab*", 3, "ab[c*]", 6, 1 },
        { "ab*", 3, "ab[*c]", 6, 1 },
        { "abc", 3, "ab*", 3, 1 },
        { "abc", 3, "abc*", 3, 1 },
        { "strglob.c", 9, "strglo*.c", 9, 1 },
        { "parangaricutirimirruaru!!!", 26, "*", 1, 1 },
        { "parangaritititero", 17, "?", 1, 0 },
        { "parangaritititero", 17, "?*", 2, 1 },
        { "parangaricutirimirruaru", 23, "paran*", 6, 1 },
        { "parangaricutirimirruaru", 23, "parruari", 8, 0 },
        { "parangaricutirimirruaru", 23, "paran*garicuti", 14, 0 },
        { "parangaricutirimirruaru", 23, "paran*garicutirimirruaru", 24, 1 },
        { "parangaricutirimirruaru", 23, "paran*ru", 8, 1 },
        { "hell yeah!", 10, "*yeah!", 6, 1 },
        { ".", 1, "*[Gg]lenda*", 11, 0 },
        { (unsigned char *)"\xDE\xAD\xBE\xEF", 4, (unsigned char *)"\xDE\xAD\xBE\xEF", 4, 1 },
        { (unsigned char *)"\xDE\xAD\xBE\xEF", 4, (unsigned char *)"\xDE\xAD[612536123\xBE]\xEF", 15, 1 },
        { (unsigned char *)"\xDE\xAD\xBE\xEF", 4, (unsigned char *)"\xDE\xAD[612536123]\xEF", 14, 0 },
        { (unsigned char *)"\n\r\t\xFE", 4, (unsigned char *)"\n\r*\xFE", 4, 1 },
    };
    size_t tests_nr = sizeof(tests) / sizeof(tests[0]), t;

    for (t = 0; t < tests_nr; t++) {
        CUTE_ASSERT(macgonuts_memglob(tests[t].data, tests[t].data_size,
                                      tests[t].pattern, tests[t].pattern_size) == tests[t].result);
    }
CUTE_TEST_CASE_END
