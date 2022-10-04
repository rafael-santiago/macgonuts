/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ndphdr.h>

#define NDP_HDR_BASE_SIZE(ctx) ( sizeof(ctx->reserv) + sizeof(ctx->target_addr) )

unsigned char *macgonuts_make_ndp_nsna_pkt(const struct macgonuts_ndp_nsna_hdr_ctx *ndphdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    if (ndphdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = NDP_HDR_BASE_SIZE(ndphdr) + ndphdr->options_size;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        return NULL;
    }

    pkt[0] = (ndphdr->reserv >> 24) & 0xFF;
    pkt[1] = (ndphdr->reserv >> 16) & 0xFF;
    pkt[2] = (ndphdr->reserv >>  8) & 0xFF;
    pkt[3] = ndphdr->reserv & 0xFF;
    memcpy(&pkt[4], &ndphdr->target_addr[0], sizeof(ndphdr->target_addr));
    if (ndphdr->options != NULL && ndphdr->options_size > 0) {
        memcpy(&pkt[NDP_HDR_BASE_SIZE(ndphdr)], ndphdr->options, ndphdr->options_size);
    }

    return pkt;
}

int macgonuts_read_ndp_nsna_pkt(struct macgonuts_ndp_nsna_hdr_ctx *ndphdr, const unsigned char *ndpbuf,
                                const size_t ndpbuf_size) {

    if (ndphdr == NULL || ndpbuf == NULL) {
        return EINVAL;
    }

    if (ndpbuf_size < NDP_HDR_BASE_SIZE(ndphdr)) {
        return EPROTO;
    }

    ndphdr->reserv = (uint32_t)ndpbuf[0] << 24 | (uint32_t)ndpbuf[1] << 16 |
                     (uint32_t)ndpbuf[2] << 16 | (uint32_t)ndpbuf[3];
    memcpy(&ndphdr->target_addr[0], &ndpbuf[4], sizeof(ndphdr->target_addr));
    if (&ndpbuf[NDP_HDR_BASE_SIZE(ndphdr)] < (ndpbuf + ndpbuf_size)) {
        ndphdr->options_size = ndpbuf_size - NDP_HDR_BASE_SIZE(ndphdr);
        ndphdr->options = (uint8_t *)malloc(ndphdr->options_size);
        if (ndphdr->options == NULL) {
            ndphdr->options_size = 0;
            return ENOMEM;
        }
        memcpy(&ndphdr->options[0], &ndpbuf[NDP_HDR_BASE_SIZE(ndphdr)], ndphdr->options_size);
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_ndp_nsna_hdr(struct macgonuts_ndp_nsna_hdr_ctx *ndphdr) {
    if (ndphdr == NULL) {
        return;
    }
    if (ndphdr->options != NULL) {
        free(ndphdr->options);
        ndphdr->options = NULL;
        ndphdr->options_size = 0;
    }
}

#undef NDP_HDR_BASE_SIZE
