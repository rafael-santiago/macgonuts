/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_filter_fmt.h>

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
