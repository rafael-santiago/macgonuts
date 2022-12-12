/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_filter_fmt.h>

unsigned char *macgonuts_format_filter(const char *filter_str, const size_t filter_str_size, size_t *fmt_filter_size) {
    const char *fp = NULL;
    const char *fp_end = NULL;
    unsigned char *fmt_filter = NULL;
    size_t temp_fmt_filter_size = 0;
    unsigned char *f_fp = NULL;
    size_t n = 0;
    if (filter_str == NULL || filter_str_size == 0 || fmt_filter_size == NULL) {
        return NULL;
    }

    temp_fmt_filter_size = (filter_str_size << 1) + 1;
    fmt_filter = (unsigned char *)malloc(temp_fmt_filter_size);
    if (fmt_filter == NULL) {
        return NULL;
    }
    memset(fmt_filter, 0, filter_str_size);

    fp = filter_str;
    fp_end = fp + filter_str_size;
    f_fp = fmt_filter;

    while (fp != fp_end) {
        if (*fp == '\\' && (fp + 1) != fp_end) {
            fp++;
            switch (*(fp)) {
                case 'n':
                    *f_fp = '\n';
                    break;

                case 't':
                    *f_fp = '\t';
                    break;

                case 'r':
                    *f_fp = '\r';
                    break;

                case 'x':
                    fp++;
#define nb2n(nb) ( isalpha(nb) ? ((toupper(nb) - 55) & 0xFF) : ((nb) - 48) & 0xFF)
                    while (fp != fp_end && isxdigit(*fp)) {
                        *f_fp = (*f_fp << 4) | nb2n(*fp);
#undef nb2n
                        n = (n + 1) & 1;
                        f_fp += (n == 0);
                        fp++;
                    }
                    fp--;
                    f_fp -= (n == 0);
                    n = 0;
                    break;

                default:
                    *f_fp = *fp;
                    break;
            }
        } else {
            *f_fp = *fp;
        }
        f_fp += 1;
        fp += 1;
    }

    *fmt_filter_size = f_fp - fmt_filter;
    fmt_filter = (unsigned char *)realloc(fmt_filter, *fmt_filter_size);
    if (fmt_filter == NULL) {
        *fmt_filter_size = 0;
    }

    return fmt_filter;
}

struct macgonuts_filter_glob_ctx **macgonuts_get_filter_glob_ctx(const char **filters, const size_t filters_nr,
                                                                 size_t *filter_globs_nr) {
    struct macgonuts_filter_glob_ctx **filter_globs = NULL;
    struct macgonuts_filter_glob_ctx **curr_filter_glob = NULL;
    const char **curr_filter = NULL;
    const char **filters_end = NULL;

    if (filters == NULL || filters_nr == 0 || filter_globs_nr == NULL) {
        return NULL;
    }

    *filter_globs_nr = 0;
    filter_globs = (struct macgonuts_filter_glob_ctx **)malloc(sizeof(struct macgonuts_filter_glob_ctx **) * filters_nr);
    if (filter_globs == NULL) {
        return NULL;
    }
    memset(filter_globs, 0, sizeof(struct macgonuts_filter_glob_ctx **) * filters_nr);

    curr_filter = filters;
    filters_end = curr_filter + filters_nr;
    curr_filter_glob = filter_globs;

    while (curr_filter != filters_end) {
        (*curr_filter_glob) = (struct macgonuts_filter_glob_ctx *)malloc(sizeof(struct macgonuts_filter_glob_ctx *));
        if (curr_filter_glob == NULL) {
            macgonuts_release_filter_glob_ctx(filter_globs, filters_nr);
            return NULL;
        }
        (*curr_filter_glob)->glob = macgonuts_format_filter((*curr_filter), strlen((*curr_filter)),
                                                            &(*curr_filter_glob)->glob_size);
        if ((*curr_filter_glob)->glob == NULL) {
            macgonuts_release_filter_glob_ctx(filter_globs, filters_nr);
            return NULL;
        }
        curr_filter_glob++;
        curr_filter++;
    }

    *filter_globs_nr = filters_nr;

    return filter_globs;
}

void macgonuts_release_filter_glob_ctx(struct macgonuts_filter_glob_ctx **filter_globs, const size_t filter_globs_nr) {
    struct macgonuts_filter_glob_ctx **curr_filter = NULL;
    struct macgonuts_filter_glob_ctx **filter_globs_end = NULL;

    if (filter_globs == NULL || filter_globs_nr == 0) {
        return;
    }

    curr_filter = filter_globs;
    filter_globs_end = curr_filter + filter_globs_nr;

    while (curr_filter != filter_globs_end) {
        if ((*curr_filter) != NULL) {
            if ((*curr_filter)->glob != NULL) {
                free((*curr_filter)->glob);
            }
            free((*curr_filter));
        }
        curr_filter++;
    }
    free(filter_globs);
}
