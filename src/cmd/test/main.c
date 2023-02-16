/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cutest.h>
#include "macgonuts_option_tests.h"
#include "macgonuts_misc_utils_tests.h"

CUTE_TEST_CASE(macgonuts_cmdtool_tests)
    CUTE_RUN_TEST(macgonuts_get_command_option_tests);
    CUTE_RUN_TEST(macgonuts_get_raw_option_tests);
    CUTE_RUN_TEST(macgonuts_get_option_tests);
    CUTE_RUN_TEST(macgonuts_get_bool_option_tests);
    CUTE_RUN_TEST(macgonuts_get_array_option_tests);
    CUTE_RUN_TEST(macgonuts_is_valid_number_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(macgonuts_cmdtool_tests)
