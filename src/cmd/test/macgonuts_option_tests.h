/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_TEST_MACGONUTS_OPTION_TESTS_H
#define MACGONUTS_CMD_TEST_MACGONUTS_OPTION_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_get_option_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_bool_option_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_command_option_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_raw_option_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_array_option_tests);

#endif // MACGONUTS_CMD_TEST_MACGONUTS_OPTION_TESTS_H
