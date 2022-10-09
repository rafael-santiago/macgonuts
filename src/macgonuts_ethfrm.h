/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ETHFRM_H
#define MACGONUTS_ETHFRM_H 1

#include <macgonuts_types.h>

#define MACGONUTS_ETHER_TYPE_ARP  0x0806
#define MACGONUTS_ETHER_TYPE_IP4  0x0800
#define MACGONUTS_ETHER_TYPE_IP6  0x08DD

struct macgonuts_ethfrm_ctx {
    uint8_t dest_hw_addr[6];
    uint8_t src_hw_addr[6];
    uint16_t ether_type;
    uint8_t *data;
    size_t data_size;
};

int macgonuts_read_ethernet_frm(struct macgonuts_ethfrm_ctx *ethfrm, const unsigned char *frm, const size_t frm_size);

unsigned char *macgonuts_make_ethernet_frm(const struct macgonuts_ethfrm_ctx *ethfrm, size_t *frm_size);

void macgonuts_release_ethfrm(struct macgonuts_ethfrm_ctx *ethfrm);

#endif // MACGONUTS_ETHFRM_H
