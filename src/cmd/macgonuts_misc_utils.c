/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_misc_utils.h>
#include <macgonuts_types.h>

int macgonuts_is_valid_number(const char *n) {
    const char *np = n;
    const char *np_end = n + strlen(n);
    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }
        np++;
    }
    return 1;
}
