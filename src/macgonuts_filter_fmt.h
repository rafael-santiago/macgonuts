/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_MACGONUTS_FILTER_FMT_H
#define MACGONUTS_MACGONUTS_FILTER_FMT_H 1

#include <macgonuts_types.h>

unsigned char *macgonuts_format_filter(const char *filter_str, const size_t filter_str_size, size_t *fmt_filter_size);

struct macgonuts_filter_glob_ctx **macgonuts_get_filter_glob_ctx(const char **filters, const size_t filters_nr,
                                                                 size_t *filter_glob_nr);

void macgonuts_release_filter_glob_ctx(struct macgonuts_filter_glob_ctx **filter_globs, const size_t filter_globs_nr);

#endif // MACGONUTS_MACGONUTS_FILTER_FMT_H
