/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_status_info_tests.h"
#include <macgonuts_status_info.h>
#include <string.h>

// INFO(Rafael): Maybe it should be better validated. Until now the majority of tests here
//               is only calls to see if something will explode or cause undefined behavior.

CUTE_TEST_CASE(macgonuts_si_error_tests)
    macgonuts_si_error("this is an error message and nothing can explode.\n");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_warn_tests)
    macgonuts_si_warn("this is a warning message and nothing can explode.\n");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_info_tests)
    macgonuts_si_info("this is a information message and nothing can explode.\n");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_set_outmode_tests)
    macgonuts_si_set_outmode(kMacgonutsSiBuf|kMacgonutsSiMonochrome);
    macgonuts_si_info("i.\n");
    macgonuts_si_warn("ii.\n");
    macgonuts_si_error("iii.\n");
    macgonuts_si_set_outmode(kMacgonutsSiSys|kMacgonutsSiColored);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_get_last_info_tests)
    char out[1<<10] = "";
    macgonuts_si_set_outmode(kMacgonutsSiBuf|kMacgonutsSiMonochrome);
    macgonuts_si_get_last_info(out, sizeof(out));
    macgonuts_si_info("i.\n");
    macgonuts_si_warn("ii.\n");
    macgonuts_si_error("iii.\n");
    CUTE_ASSERT(macgonuts_si_get_last_info(NULL, sizeof(out)) == ERANGE);
    CUTE_ASSERT(macgonuts_si_get_last_info(out, 0) == ERANGE);
    CUTE_ASSERT(macgonuts_si_get_last_info(out, sizeof(out)) == EXIT_SUCCESS);
    CUTE_ASSERT(strcmp(out, "info: i.\nwarn: ii.\nerror: iii.\n") == 0);
    macgonuts_si_set_outmode(kMacgonutsSiSys|kMacgonutsSiColored);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_print_tests)
    macgonuts_si_print("this is a print call and nothing can explode.\n");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_mode_enter_announce_tests)
    macgonuts_si_mode_enter_announce("test");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_si_mode_leave_announce_tests)
    macgonuts_si_mode_leave_announce("test");
CUTE_TEST_CASE_END
