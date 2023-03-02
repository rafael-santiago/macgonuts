/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_routeconv.h>

static int is_outward_dest4(const uint8_t *dest_addr, const uint8_t *net_mask, const uint8_t *lo_addr);

static int is_outward_dest6(const uint8_t *dest_addr, const uint8_t *net_mask, const uint8_t *lo_addr);

#define andmskbytene(m, a, b) ( ((m) & (a)) != ((m) & (b)) )

int macgonuts_is_outward_dest(const uint8_t *dest_addr, const uint8_t *net_mask,
                              const uint8_t *lo_addr, const size_t addr_size) {
    static int (*is_outward_dest)(const uint8_t *, const uint8_t *, const uint8_t *) = NULL;

    switch (addr_size) {
        case 4:
            is_outward_dest = is_outward_dest4;
            break;

        case 16:
            is_outward_dest = is_outward_dest6;
            break;

        default:
            // INFO(Rafael): It should never happen in normal conditions.
            return 0;
    }

    assert(is_outward_dest != NULL);

    return is_outward_dest(dest_addr, net_mask, lo_addr);
}

static int is_outward_dest4(const uint8_t *dest_addr, const uint8_t *net_mask, const uint8_t *lo_addr) {
    return (andmskbytene(net_mask[0], dest_addr[0], lo_addr[0])
            || andmskbytene(net_mask[1], dest_addr[1], lo_addr[1])
            || andmskbytene(net_mask[2], dest_addr[2], lo_addr[2])
            || andmskbytene(net_mask[3], dest_addr[3], lo_addr[3]));
}

static int is_outward_dest6(const uint8_t *dest_addr, const uint8_t *net_mask, const uint8_t *lo_addr) {
    return (andmskbytene(net_mask[ 0], dest_addr[ 0], lo_addr[ 0])
            || andmskbytene(net_mask[ 1], dest_addr[ 1], lo_addr[ 1])
            || andmskbytene(net_mask[ 2], dest_addr[ 2], lo_addr[ 2])
            || andmskbytene(net_mask[ 3], dest_addr[ 3], lo_addr[ 3])
            || andmskbytene(net_mask[ 4], dest_addr[ 4], lo_addr[ 4])
            || andmskbytene(net_mask[ 5], dest_addr[ 5], lo_addr[ 5])
            || andmskbytene(net_mask[ 6], dest_addr[ 6], lo_addr[ 6])
            || andmskbytene(net_mask[ 7], dest_addr[ 7], lo_addr[ 7])
            || andmskbytene(net_mask[ 8], dest_addr[ 8], lo_addr[ 8])
            || andmskbytene(net_mask[ 9], dest_addr[ 9], lo_addr[ 9])
            || andmskbytene(net_mask[10], dest_addr[10], lo_addr[10])
            || andmskbytene(net_mask[11], dest_addr[11], lo_addr[11])
            || andmskbytene(net_mask[12], dest_addr[12], lo_addr[12])
            || andmskbytene(net_mask[13], dest_addr[13], lo_addr[13])
            || andmskbytene(net_mask[14], dest_addr[14], lo_addr[14])
            || andmskbytene(net_mask[15], dest_addr[15], lo_addr[15])
);
}

#undef andmskbytene
