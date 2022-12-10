/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_FILTER_FMT_H
#define MACGONUTS_CMD_MACGONUTS_FILTER_FMT_H 1

#include <macgonuts_types.h>

unsigned char *macgonuts_format_filter(const char *filter_str, const size_t filter_str_size, size_t *fmt_filter_size);

#endif // MACGONUTS_CMD_MACGONUTS_FILTER_FMT_H
