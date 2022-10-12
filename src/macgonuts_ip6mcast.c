/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ip6mcast.h>

int macgonuts_get_multicast_addr(uint8_t *mcast, const size_t mcast_size,
                                  const uint8_t *haddr, const size_t haddr_size) {
    if (mcast == NULL || haddr == NULL || mcast_size != 16 || haddr_size != 16) {
        return EINVAL;
    }
    mcast[ 0] = 0xFF;
    mcast[ 1] = 0x02;
    mcast[ 2] = 0x00;
    mcast[ 3] = 0x00;
    mcast[ 4] = 0x00;
    mcast[ 5] = 0x00;
    mcast[ 6] = 0x00;
    mcast[ 7] = 0x00;
    mcast[ 8] = 0x00;
    mcast[ 9] = 0x00;
    mcast[10] = 0x00;
    mcast[11] = 0x01;
    mcast[12] = 0xFF;
    memcpy(&mcast[13], &haddr[13], 3);
    return EXIT_SUCCESS;
}

int macgonuts_get_unsolicited_multicast_addr(uint8_t *mcast, const size_t mcast_size) {
    if (mcast == NULL || mcast_size != 16) {
        return EINVAL;
    }
    mcast[ 0] = 0xFF;
    mcast[ 1] = 0x02;
    mcast[ 2] = 0x00;
    mcast[ 3] = 0x00;
    mcast[ 4] = 0x00;
    mcast[ 5] = 0x00;
    mcast[ 6] = 0x00;
    mcast[ 7] = 0x00;
    mcast[ 8] = 0x00;
    mcast[ 9] = 0x00;
    mcast[10] = 0x00;
    mcast[11] = 0x00;
    mcast[12] = 0x00;
    mcast[13] = 0x00;
    mcast[14] = 0x00;
    mcast[15] = 0x01;
    return EXIT_SUCCESS;
}
