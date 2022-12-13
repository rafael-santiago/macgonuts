/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_memglob.h>

int macgonuts_memglob(const unsigned char *data, const size_t data_size,
                      const unsigned char *pattern, const size_t pattern_size) {
    const char *d, *d_end;
    const char *p, *p_end, *lp;
    int matches = 1;

    if (data == NULL || pattern == NULL) {
        return 0;
    }

    d = data;
    d_end = d + data_size;
    p = pattern;
    p_end = p + pattern_size;

    if ((pattern_size == 1 && *pattern == '*') || p == p_end) {
        return 1;
    }

    while (matches && p != p_end && d != d_end) {
        switch (*p) {
            case '*':
                matches = ((p + 1) == p_end) && ((d + 1) == d_end);

                while (!matches && d != d_end) {
                    matches = macgonuts_memglob(d, d_end - d, p + 1, p_end - (p + 1));
                    d++;
                }

                if (matches) {
                    d = d_end;
                    p = p_end;
                }

                goto macgonuts_memglob_epilogue;

            case '?':
                matches = (d != d_end);
                break;

            case '[':
                matches = 0;
                p++;

                while (!matches && d != d_end && *p != ']') {
                    matches = (*d == *p);
                    p++;
                }

                if (matches && *p != ']') {
                    while (*p != ']' && p != p_end) {
                        p++;
                    }
                }
                break;

            default:
                matches = (*d == *p);
                break;
        }
        p++;
        d++;
    }

macgonuts_memglob_epilogue:
    if (matches && d == d_end && p != p_end && *p == '*') {
        p++;
    }

    matches = (matches && (p == p_end && d == d_end));

    return matches;
}
