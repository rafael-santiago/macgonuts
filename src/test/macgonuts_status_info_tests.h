/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_STATUS_INFO_TESTS_H
#define MACGONUTS_TEST_MACGONUTS_STATUS_INFO_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_si_error_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_warn_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_info_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_set_outmode_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_get_last_info_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_print_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_mode_enter_announce_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_si_mode_leave_announce_tests);

#endif // MACGONUTS_TEST_MACGONUTS_STATUS_INFO_TESTS_H
