/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_printpkt_if.h>
#include <cmd/macgonuts_memglob.h>

int macgonuts_printpkt_if(const unsigned char *ethfrm, const size_t ethfrm_size,
                          struct macgonuts_filter_glob_ctx **filter_globs,
                          const size_t filter_globs_nr) {
    struct macgonuts_filter_glob_ctx **curr_filter = NULL;
    struct macgonuts_filter_glob_ctx **filter_globs_end = NULL;
    int found = 0;

    if (ethfrm == NULL || ethfrm_size == 0 || filter_globs == NULL || filter_globs_nr == 0) {
        return 0;
    }

    curr_filter = filter_globs;
    filter_globs_end = curr_filter + filter_globs_nr;

    do {
        found = (macgonuts_memglob(ethfrm, ethfrm_size, (*curr_filter)->glob, (*curr_filter)->glob_size) != 0);
        curr_filter++;
    } while (curr_filter != filter_globs_end && !found);

    return found;
}

