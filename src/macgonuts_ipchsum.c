/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ipchsum.h>

uint16_t macgonuts_eval_ipchsum(const void *data, const size_t data_size) {
    const uint8_t *bp = NULL;
    const uint8_t *bp_end = NULL;
    uint32_t sum = 0;

    if (data == NULL || data_size == 0) {
        return 0;
    }

    bp = (const uint8_t *)data;
    bp_end = bp + data_size;

    while (bp < bp_end) {
        sum += (uint16_t)bp[0] << 8 | (uint16_t)(((bp + 1) != bp_end) ? bp[1] : 0);
        bp += 2;
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return (uint16_t)(~sum);
}
