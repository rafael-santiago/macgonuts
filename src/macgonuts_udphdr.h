/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_UDPHDR_H
#define MACGONUTS_UDPHDR_H 1

#include <macgonuts_types.h>

struct macgonuts_udphdr_ctx {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t chsum;
    uint8_t *payload;
    size_t payload_size;
};

unsigned char *macgonuts_make_udp_pkt(const struct macgonuts_udphdr_ctx *udphdr, size_t *pkt_size,
                                      const void *pheader, const size_t pheader_size);

int macgonuts_read_udp_pkt(struct macgonuts_udphdr_ctx *udphdr, const unsigned char *udpbuf, const size_t udpbuf_size);

void macgonuts_release_udphdr(struct macgonuts_udphdr_ctx *udphdr);


#endif // MACGONUTS_UDPHDR_H
