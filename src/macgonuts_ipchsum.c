/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ipchsum.h>

uint16_t macgonuts_eval_ipchsum(const void *data, const size_t data_size,
                                const void *pseudo_header, const size_t pseudo_header_size) {
    const uint8_t *bp[2] = { NULL, NULL };
    const uint8_t *bp_end[2] = { NULL,  NULL };
    uint32_t sum = 0;
    size_t b;

    if (data == NULL || data_size == 0) {
        return 0;
    }

    bp[0] = (const uint8_t *)data;
    bp_end[0] = bp[0] + data_size;

    bp[1] = (const uint8_t *)pseudo_header;
    bp_end[1] = bp[1] + pseudo_header_size;

    for (b = 0; bp[b] != NULL && b < 2; b++) {
        while (bp[b] < bp_end[b]) {
            sum += (uint16_t)bp[b][0] << 8 | (uint16_t)(((bp[b] + 1) != bp_end[b]) ? bp[b][1] : 0);
            bp[b] += 2;
        }
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return (uint16_t)(~sum);
}
