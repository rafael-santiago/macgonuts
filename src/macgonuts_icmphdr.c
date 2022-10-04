/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_icmphdr.h>

#define ICMP_BASE_HDR_SIZE(ctx) (sizeof(ctx->type) + sizeof(ctx->code) + sizeof(ctx->chsum))

unsigned char *macgonuts_make_icmp_pkt(const struct macgonuts_icmphdr_ctx *icmphdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;

    if (icmphdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = ICMP_BASE_HDR_SIZE(icmphdr) + icmphdr->payload_size;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        *pkt_size = 0;
        return NULL;
    }

    pkt[0] = icmphdr->type;
    pkt[1] = icmphdr->code;
    pkt[2] = (icmphdr->chsum >> 8) & 0xFF;
    pkt[3] = icmphdr->chsum & 0xFF;
    if (icmphdr->payload_size > 0 && icmphdr->payload != NULL) {
        memcpy(&pkt[4], icmphdr->payload, icmphdr->payload_size);
    }

    return pkt;
}

int macgonuts_read_icmp_pkt(struct macgonuts_icmphdr_ctx *icmphdr, const unsigned char *icmpbuf, const size_t icmpbuf_size) {
    if (icmphdr == NULL || icmpbuf == NULL) {
        return EINVAL;
    }

    if (icmpbuf_size < ICMP_BASE_HDR_SIZE(icmphdr)) {
        return EPROTO;
    }

    icmphdr->type = icmpbuf[0];
    icmphdr->code = icmpbuf[1];
    icmphdr->chsum = (uint16_t)icmpbuf[2] << 8 | (uint16_t)icmpbuf[3];
    if (icmpbuf_size > ICMP_BASE_HDR_SIZE(icmphdr)) {
        icmphdr->payload_size = icmpbuf_size - ICMP_BASE_HDR_SIZE(icmphdr);
        icmphdr->payload = (uint8_t *)malloc(icmphdr->payload_size);
        if (icmphdr->payload == NULL) {
            return ENOMEM;
        }
        memcpy(icmphdr->payload, &icmpbuf[4], icmphdr->payload_size);
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_icmphdr(struct macgonuts_icmphdr_ctx *icmphdr) {
    if (icmphdr == NULL) {
        return;
    }
    if (icmphdr->payload != NULL) {
        free(icmphdr->payload);
        icmphdr->payload = NULL;
        icmphdr->payload_size = 0;
    }
}

#undef ICMP_BASE_HDR_SIZE
