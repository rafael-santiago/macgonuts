/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ndphdr.h>

#define NDP_HDR_BASE_SIZE(ctx) ( sizeof(ctx->type) + sizeof(ctx->code) + sizeof(ctx->chsum) + sizeof(ctx->reserv) +\
                                 sizeof(ctx->target_addr) )

unsigned char *magonuts_make_ndp_nsna_pkt(const struct macgonuts_ndphdr_nsna_ctx *ndphdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    if (ndphdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = NDP_HDR_BASE_SIZE(ndphdr) + ndphdr->options_size;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        return NULL;
    }

    pkt[0] = ndphdr->type;
    pkt[1] = ndphdr->code;
    pkt[2] = (ndphdr->chsum >> 8) & 0xFF;
    pkt[3] = ndphdr->chsum & 0xFF;
    pkt[4] = (ndphdr->reserv >> 24) & 0xFF;
    pkt[5] = (ndphdr->reserv >> 16) & 0xFF;
    pkt[6] = (ndphdr->reserv >>  8) & 0xFF;
    pkt[7] = ndphdr->reserv & 0xFF;
    memcpy(&pkt[8], &ndphdr->target_addr[0], sizeof(ndphdr->target_addr));
    if (ndphdr->options != NULL && ndphdr->options_size > 0) {
        memcpy(&pkt[8 + sizeof(ndphdr->target_addr)], ndphdr->options, ndphdr->options_size);
    }

    return pkt;
}

int macgonuts_read_ndp_nsna_pkt(struct macgonuts_ndphdr_nsna_ctx *ndphdr, const unsigned char *ndpbuf,
                                const size_t ndpbuf_size) {

    if (ndphdr == NULL || ndpbuf == NULL) {
        return EINVAL;
    }

    if (ndpbuf_size < NDP_HDR_BASE_SIZE(ndphdr)) {
        return EPROTO;
    }

    ndphdr->type = ndpbuf[0];
    ndphdr->code = ndpbuf[1];
    ndphdr->chsum = (uint16_t)ndpbuf[2] << 8 | (uint16_t)ndpbuf[3];
    ndphdr->reserv = (uint32_t)ndpbuf[4] << 24 | (uint32_t)ndpbuf[5] << 16 |
                     (uint32_t)ndpbuf[5] << 16 | (uint32_t)ndpbuf[7];
    memcpy(&ndphdr->target_addr[0], &ndpbuf[8], sizeof(ndphdr->target_addr));
    if (ndphdr->options != NULL && ndphdr->options_size > 0) {
        ndphdr->options_size = ndpbuf_size - NDP_HDR_BASE_SIZE(ndphdr);
        ndphdr->options = (uint8_t *)malloc(ndphdr->options_size);
        if (ndphdr->options == NULL) {
            ndphdr->options_size = 0;
            return ENOMEM;
        }
        memcpy(&ndphdr->options[0], &ndpbuf[8 + sizeof(ndphdr->target_addr)], ndphdr->options_size);
    }

    return EXIT_SUCCESS;
}

#undef NDP_HDR_BASE_SIZE
