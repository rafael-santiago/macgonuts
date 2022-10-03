/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_IP6HDR_H
#define MACGINUTS_IP6HDR_H 1

#include <macgonuts_types.h>

struct macgonuts_ip6hdr_ctx {
    uint8_t version;
    uint8_t priority;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dest_addr[16];
    uint8_t *payload;
};

unsigned char *macgonuts_make_ip6_pkt(const struct macgonuts_ip6hdr_ctx *ip6hdr, size_t *pkt_size);

int macgonuts_read_ip6_pkt(struct macgonuts_ip6hdr_ctx *ip6hdr, const unsigned char *ip6buf, const size_t ip6buf_size);

void macgonuts_release_ip6hdr(struct macgonuts_ip6hdr_ctx *ip6hdr);

#endif // MACGONUTS_IP6HDR_H
