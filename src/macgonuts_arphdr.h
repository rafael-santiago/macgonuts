/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ARPHDR_H
#define MACGONUTS_ARPHDR_H 1

#include <macgonuts_types.h>

typedef enum macgonuts_arp_oper_code {
    kARPOperFirstReserved = 0,
    kARPOperRequest,
    kARPOperReply,
    kARPOperRequestReverse,
    kARPOperReplyReverse,
    kARPOperDRARPRequest,
    kARPOperDRARPReply,
    kARPOperDRARPError,
    kARPOperInARPRequest,
    kARPOperInARPReply,
    kARPOperNAK,
    kARPOperMARSRequest,
    kARPOperMARSMulti,
    kARPOperMARSMServ,
    kARPOperMARSJoin,
    kARPOperMARSLeave,
    kARPOperMARSNAK,
    kARPOperMARSUnserv,
    kARPOperMARSSJoin,
    kARPOperMARSSLeave,
    kARPOperGrouplistRequest,
    kARPOperGrouplistReply,
    kARPOperMARSRedirectMap,
    kARPOperMAPSOSUNARP,
    kARPOperOP_EXP1,
    kARPOperOP_EXP2,
    // INFO(Rafael): a bunch of unassigned.
    kARPOperLastReserved = 65535,
}macgonuts_arp_oper_code_t;

struct macgonuts_arphdr_ctx {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t *sha;
    uint8_t *spa;
    uint8_t *tha;
    uint8_t *tpa;
};

unsigned char *macgonuts_make_arp_pkt(const struct macgonuts_arphdr_ctx *arphdr, size_t *pkt_size);

int macgonuts_read_arp_pkt(struct macgonuts_arphdr_ctx *arphdr, const unsigned char *arpbuf, const size_t arpbuf_size);

void macgonuts_release_arphdr(struct macgonuts_arphdr_ctx *arphdr);

#endif // MACGONUTS_ARPHDR_H

