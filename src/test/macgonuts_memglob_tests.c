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
        { (unsigned char *)"abc", 3, (unsigned char *)"abc", 3, 1 },
        { (unsigned char *)"abc", 3, (unsigned char *)"ab", 2, 0 },
        { (unsigned char *)"abc", 3, (unsigned char *)"a?c", 3, 1 },
        { (unsigned char *)"abc", 3, (unsigned char *)"ab[abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.c]", 57, 1 },
        { (unsigned char *)"abc", 3, (unsigned char *)"ab[abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.?]", 57, 0 },
        { (unsigned char *)"ab*", 3, (unsigned char *)"ab[c*]", 6, 1 },
        { (unsigned char *)"ab*", 3, (unsigned char *)"ab[*c]", 6, 1 },
        { (unsigned char *)"abc", 3, (unsigned char *)"ab*", 3, 1 },
        { (unsigned char *)"abc", 3, (unsigned char *)"abc*", 3, 1 },
        { (unsigned char *)"strglob.c", 9, (unsigned char *)"strglo*.c", 9, 1 },
        { (unsigned char *)"parangaricutirimirruaru!!!", 26, (unsigned char *)"*", 1, 1 },
        { (unsigned char *)"parangaritititero", 17, (unsigned char *)"?", 1, 0 },
        { (unsigned char *)"parangaritititero", 17, (unsigned char *)"?*", 2, 1 },
        { (unsigned char *)"parangaricutirimirruaru", 23, (unsigned char *)"paran*", 6, 1 },
        { (unsigned char *)"parangaricutirimirruaru", 23, (unsigned char *)"parruari", 8, 0 },
        { (unsigned char *)"parangaricutirimirruaru", 23, (unsigned char *)"paran*garicuti", 14, 0 },
        { (unsigned char *)"parangaricutirimirruaru", 23, (unsigned char *)"paran*garicutirimirruaru", 24, 1 },
        { (unsigned char *)"parangaricutirimirruaru", 23, (unsigned char *)"paran*ru", 8, 1 },
        { (unsigned char *)"hell yeah!", 10, (unsigned char *)"*yeah!", 6, 1 },
        { (unsigned char *)".", 1, (unsigned char *)"*[Gg]lenda*", 11, 0 },
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
