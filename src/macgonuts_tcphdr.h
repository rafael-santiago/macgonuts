/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TCPHDR_H
#define MACGONUTS_TCPHDR_H 1

#include <macgonuts_types.h>

struct macgonuts_tcphdr_ctx {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seqno;
    uint32_t ackno;
    uint16_t doff_reserv_flags;
    uint16_t window;
    uint16_t chsum;
    uint16_t urgptr;
    uint8_t *options;
    size_t options_size;
    uint8_t *payload;
    size_t payload_size;
};

unsigned char *macgonuts_make_tcp_pkt(const struct macgonuts_tcphdr_ctx *tcphdr, size_t *pkt_size);

int macgonuts_read_tcp_pkt(struct macgonuts_tcphdr_ctx *tcphdr, const unsigned char *tcpbuf, const size_t tcpbuf_size);

void macgonuts_release_tcphdr(struct macgonuts_tcphdr_ctx *tcphdr);


#endif // MACGONUTS_TCPHDR_H

