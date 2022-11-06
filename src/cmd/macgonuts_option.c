/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_option.h>
#include <string.h>
#include <stdio.h>

static const char **g_Argv = NULL;

static int g_Argc = 0;

void macgonuts_set_argc_argv(const int argc, const char **argv) {
    g_Argc = argc;
    g_Argv = argv;
}

const char *macgonuts_get_command_option(void) {
    if (g_Argv == NULL || g_Argc < 2) {
        return NULL;
    }
    return &g_Argv[1][0];
}

const char *macgonuts_get_raw_option(const size_t option_index) {
    if (g_Argv == NULL || g_Argc == 0 || option_index > g_Argc) {
        return NULL;
    }
    return &g_Argv[option_index][0];
}

const char *macgonuts_get_option(const char *option, const char *default_value) {
    const char **ap = NULL;
    const char **ap_end = NULL;
    char temp[1<<10];
    size_t temp_size;

    if (option == NULL || g_Argv == NULL || g_Argc == 0) {
        return default_value;
    }

    temp_size = snprintf(temp, sizeof(temp), "--%s=", option);
    ap = g_Argv;
    ap_end = ap + g_Argc;

    while (ap != ap_end) {
        if (strstr(*ap, temp) == *ap) {
            return (*ap + temp_size);
        }
        ap++;
    }

    return default_value;
}

int macgonuts_get_bool_option(const char *option, const int default_value) {
    const char **ap = NULL;
    const char **ap_end = NULL;
    char temp[1<<10];
    size_t temp_size;

    if (option == NULL || g_Argv == NULL || g_Argc == 0) {
        return default_value;
    }

    temp_size = snprintf(temp, sizeof(temp), "--%s", option);

    ap = g_Argv;
    ap_end = ap + g_Argc;

    while (ap != ap_end) {
        if (strcmp(temp, *ap) == 0) {
            return 1;
        }
        ap++;
    }

    return 0;
}
