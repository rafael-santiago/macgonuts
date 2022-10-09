/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_NDPHDR_H
#define MACGONUTS_NDPHDR_H 1

#include <macgonuts_icmphdr.h>

typedef enum macgonuts_ndp_message_type {
    kNDPMsgTypeRouterSolicitation = 133,
    kNDPMsgTypeRouterAdvertisement,
    kNDPMsgTypeNeighborSolicitation,
    kNDPMsgTypeNeighborAdvertisement,
    kNDPMsgTypeRedirectMessageFormat,
}macgonuts_ndp_message_type_t;

struct macgonuts_ndp_nsna_hdr_ctx {
    uint32_t reserv;
    uint32_t target_addr[4];
    uint8_t *options;
    size_t options_size;
};

unsigned char *macgonuts_make_ndp_nsna_pkt(const struct macgonuts_ndp_nsna_hdr_ctx *ndphdr, size_t *pkt_size);

int macgonuts_read_ndp_nsna_pkt(struct macgonuts_ndp_nsna_hdr_ctx *ndphdr, const unsigned char *ndpbuf,
                                const size_t ndpbuf_size);

void macgonuts_release_ndp_nsna_hdr(struct macgonuts_ndp_nsna_hdr_ctx *ndphdr);

#endif // MACGONUTS_NDPHDR_H
