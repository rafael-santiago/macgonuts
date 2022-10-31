/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_IP4HDR_H
#define MACGONUTS_IP4HDR_H 1

#include <macgonuts_types.h>

struct macgonuts_ip4hdr_ctx {
    uint8_t version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint16_t flag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t chsum;
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t *options;
    size_t options_size;
    uint8_t *payload;
    size_t payload_size;
};

struct macgonuts_ip4_pseudo_hdr_ctx {
    uint8_t src_addr[4];
    uint8_t dest_addr[4];
    uint8_t zprotolen[4];
};

unsigned char *macgonuts_make_ip4_pkt(const struct macgonuts_ip4hdr_ctx *ip4hdr, size_t *pkt_size,
                                      const int compute_checksum);

int macgonuts_read_ip4_pkt(struct macgonuts_ip4hdr_ctx *ip4hdr, const unsigned char *ip4buf, const size_t ip4buf_size);

void macgonuts_release_ip4hdr(struct macgonuts_ip4hdr_ctx *ip4hdr);

#endif // MACGONUTS_IP4HDR_H
