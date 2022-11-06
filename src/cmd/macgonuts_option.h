/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_OPTION_H
#define MACGONUTS_CMD_MACGONUTS_OPTION_H 1

#include <stdlib.h>

void macgonuts_set_argc_argv(const int argc, const char **argv);

const char *macgonuts_get_option(const char *option, const char *default_value);

int macgonuts_get_bool_option(const char *option, const int default_value);

const char *macgonuts_get_command_option(void);

const char *macgonuts_get_raw_option(const size_t option_index);

#endif // MACGONUTS_CMD_OPTION_H
