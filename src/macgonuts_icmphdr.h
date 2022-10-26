/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ICMPHDR_H
#define MACGONUTS_ICMPHDR_H 1

#include <macgonuts_types.h>
#include <macgonuts_ip6hdr.h>

struct macgonuts_icmphdr_ctx {
    uint8_t type;
    uint8_t code;
    uint16_t chsum;
    uint8_t *payload;
    size_t payload_size;
};

unsigned char *macgonuts_make_icmp_pkt(const struct macgonuts_icmphdr_ctx *icmphdr, size_t *pkt_size,
                                       const void *pheader, const size_t pheader_size);

int macgonuts_read_icmp_pkt(struct macgonuts_icmphdr_ctx *icmphdr, const unsigned char *icmpbuf, const size_t icmpbuf_size);

void macgonuts_release_icmphdr(struct macgonuts_icmphdr_ctx *icmphdr);

#endif // MACGONUTS_ICMPHDR_H
