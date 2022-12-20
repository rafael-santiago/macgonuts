/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_misc_utils_tests.h"
#include <cmd/macgonuts_misc_utils.h>

CUTE_TEST_CASE(macgonuts_is_valid_number_tests)
    struct test_ctx {
        const char *n;
        const int expected;
    } test_vector[] = {
        { "0", 1 },
        { "0.", 0 },
        { "1234", 1 },
        { "-1234", 0 },
        { "xablauz", 0 },
        { "17892317298319", 1 },
        { "0x1234", 0 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_is_valid_number(test->n) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END
