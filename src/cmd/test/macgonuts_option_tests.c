/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_option_tests.h"
#include <cmd/macgonuts_option.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_get_option_tests)
    static char command[] = "command";
    static char opt1[] = "--opt1=o1";
    static char opt2[] = "--opt2=o2";
    static char *argv[] = {
        command,
        opt1,
        opt2,
    };
    static int argc = sizeof(argv) / sizeof(argv[0]);
    const char *value = NULL;
    CUTE_ASSERT(macgonuts_get_option("null", NULL) == NULL);
    macgonuts_set_argc_argv(argc, (const char **)argv);
    value = macgonuts_get_option("null", "(null)");
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "(null)") == 0);
    value = macgonuts_get_option("opt1", NULL);
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "o1") == 0);
    value = macgonuts_get_option("opt2", NULL);
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "o2") == 0);
    macgonuts_set_argc_argv(0, NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_bool_option_tests)
    static char command[] = "command";
    static char opt1[] = "--opt1=o1";
    static char opt2[] = "--opt2=o2";
    static char bool_opt[] = "--bool-opt";
    static char *argv[] = {
        command,
        opt1,
        opt2,
        bool_opt,
    };
    static int argc = sizeof(argv) / sizeof(argv[0]);
    const char *value = NULL;
    CUTE_ASSERT(macgonuts_get_bool_option("null", 1) == 1);
    macgonuts_set_argc_argv(argc, (const char **)argv);
    CUTE_ASSERT(macgonuts_get_bool_option("null", 0) == 0);
    CUTE_ASSERT(macgonuts_get_bool_option("bool-opt", 0) == 1);
    macgonuts_set_argc_argv(0, NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_command_option_tests)
    static char app[] = "app";
    static char command[] = "command";
    static char opt1[] = "--opt1=o1";
    static char opt2[] = "--opt2=o2";
    static char bool_opt[] = "--bool-opt";
    static char *argv[] = {
        app,
        command,
        opt1,
        opt2,
        bool_opt,
    };
    static int argc = sizeof(argv) / sizeof(argv[0]);
    const char *cmd = NULL;
    CUTE_ASSERT(macgonuts_get_command_option() == NULL);
    macgonuts_set_argc_argv(argc, (const char **)argv);
    cmd = macgonuts_get_command_option();
    CUTE_ASSERT(cmd != NULL);
    CUTE_ASSERT(strcmp(cmd, "command") == 0);
    macgonuts_set_argc_argv(0, NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_raw_option_tests)
    static char command[] = "command";
    static char opt1[] = "--opt1=o1";
    static char opt2[] = "--opt2=o2";
    static char bool_opt[] = "--bool-opt";
    static char *argv[] = {
        command,
        opt1,
        opt2,
        bool_opt,
    };
    static int argc = sizeof(argv) / sizeof(argv[0]);
    const char *value = NULL;
    CUTE_ASSERT(macgonuts_get_raw_option(0) == NULL);
    macgonuts_set_argc_argv(argc, (const char **)argv);
    value = macgonuts_get_raw_option(0);
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "command") == 0);
    value = macgonuts_get_raw_option(1);
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "--opt1=o1") == 0);
    value = macgonuts_get_raw_option(2);
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "--opt2=o2") == 0);
    value = macgonuts_get_raw_option(3);
    CUTE_ASSERT(value != NULL);
    CUTE_ASSERT(strcmp(value, "--bool-opt") == 0);
    macgonuts_set_argc_argv(0, NULL);
CUTE_TEST_CASE_END
