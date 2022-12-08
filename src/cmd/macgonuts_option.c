/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_option.h>

static const char **g_Argv = NULL;

static int g_Argc = 0;

static char **tokenize_array_option_value(const char *option_value,
                                          const size_t option_value_size, size_t *array_size);

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

char **macgonuts_get_array_option(const char *option, const char *default_value, size_t *array_size) {
    const char *option_value = NULL;
    size_t option_value_size = 0;

    if (array_size == NULL) {
        return NULL;
    }

    *array_size = 0;

    option_value = macgonuts_get_option(option, default_value);
    option_value_size = (option_value != NULL) ? strlen(option_value) : 0;

    if (option_value_size == 0) {
        return NULL;
    }

    return tokenize_array_option_value(option_value, option_value_size, array_size);
}

void macgonuts_free_array_option_value(char **array, const size_t array_size) {
    size_t a = 0;
    if (array == NULL || array_size == 0) {
        return;
    }
    while (a < array_size) {
        free(array[a++]);
    }
    free(array);
}

static char **tokenize_array_option_value(const char *option_value,
                                          const size_t option_value_size, size_t *array_size) {
    char **array = NULL, **a_item = NULL;
    const char *op = option_value, *l_op = NULL;
    const char *op_end = op + option_value_size;
    size_t a_item_size = 0;

    *array_size = 1; // INFO(Rafael): At least one item it will have.

    while (op < op_end) {
        if (*op == '\\') {
            op += 2;
            if (op >= op_end) {
                continue;
            }
        }
        *array_size += (*op == ',');
        op++;
    }

    array = (char **)malloc(sizeof(const char **) * (*array_size));
    if (array == NULL) {
        *array_size = 0;
        return NULL;
    }

    a_item = array;
    l_op = op = option_value;
    while (op < op_end) {
        if (*op == '\\') {
            op += 2;
            if (op >= op_end) {
                continue;
            }
        }
        if (*op == ',' || (op + 1) >= op_end) {
            a_item_size = op - l_op + ((op + 1) >= op_end);
            *a_item = (char *) malloc(a_item_size + 1);
            if (a_item == NULL) {
                *array_size = (a_item - array - 1);
                return array;
            }
            memset(*a_item, 0, a_item_size + 1);
            memcpy(*a_item, l_op, a_item_size);
            l_op = op + 1;
            a_item++;
        }
        op++;
    }

    return array;
}
