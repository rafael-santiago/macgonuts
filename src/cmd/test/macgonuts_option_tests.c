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

CUTE_TEST_CASE(macgonuts_get_array_option_tests)
    static char command[] = "hey_ho_lets_go";
    static char opt1[] = "--r.a.m.o.n.e.s=joe,dee-dee,mark,johnny,tommy,richie,c.j,clem";
    static char opt2[] = "--we-are-motorhead-and-we-play-rock-n-roll=lemmy,eddie,philty,"
                         "phil,mikkey,wurzel,larry,lucas,brian,pete";
    static char *argv[] = {
        command,
        opt1,
        opt2,
    };
    static int argc = sizeof(argv) / sizeof(argv[0]);
    size_t array_size = 42;
    char **array = NULL;
    macgonuts_set_argc_argv(argc, (const char **)argv);
    array = macgonuts_get_array_option("engenheiros-do-hitaboraii", NULL, &array_size);
    CUTE_ASSERT(array == NULL);
    CUTE_ASSERT(array_size == 0);
    array = macgonuts_get_array_option("r.a.m.o.n.e.s", NULL, &array_size);
    CUTE_ASSERT(array != NULL);
    CUTE_ASSERT(strcmp(array[0], "joe") == 0);
    CUTE_ASSERT(strcmp(array[1], "dee-dee") == 0);
    CUTE_ASSERT(strcmp(array[2], "mark") == 0);
    CUTE_ASSERT(strcmp(array[3], "johnny") == 0);
    CUTE_ASSERT(strcmp(array[4], "tommy") == 0);
    CUTE_ASSERT(strcmp(array[5], "richie") == 0);
    CUTE_ASSERT(strcmp(array[6], "c.j") == 0);
    CUTE_ASSERT(strcmp(array[7], "clem") == 0);
    // INFO(Rafael): Those broke calls cannot explode.
    macgonuts_free_array_option_value(NULL, 0);
    macgonuts_free_array_option_value(array, 0);
    macgonuts_free_array_option_value(NULL, array_size);
    // INFO(Rafael): If it is broken the memory leak system will complain.
    macgonuts_free_array_option_value(array, array_size);
    array = macgonuts_get_array_option("we-are-motorhead-and-we-play-rock-n-roll", NULL, &array_size);
    CUTE_ASSERT(array != NULL);
    CUTE_ASSERT(strcmp(array[0], "lemmy") == 0);
    CUTE_ASSERT(strcmp(array[1], "eddie") == 0);
    CUTE_ASSERT(strcmp(array[2], "philty") == 0);
    CUTE_ASSERT(strcmp(array[3], "phil") == 0);
    CUTE_ASSERT(strcmp(array[4], "mikkey") == 0);
    CUTE_ASSERT(strcmp(array[5], "wurzel") == 0);
    CUTE_ASSERT(strcmp(array[6], "larry") == 0);
    CUTE_ASSERT(strcmp(array[7], "lucas") == 0);
    CUTE_ASSERT(strcmp(array[8], "brian") == 0);
    CUTE_ASSERT(strcmp(array[9], "pete") == 0);
    macgonuts_free_array_option_value(array, array_size);
    macgonuts_set_argc_argv(0, NULL);
CUTE_TEST_CASE_END
