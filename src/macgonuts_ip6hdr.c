/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ip6hdr.h>

#define IP6_HDR_BASE_SIZE(ctx) ( 1 /* INFO(Rafael): version and priority. */+\
                                 (sizeof(ctx->flow_label) - 1) + sizeof(ctx->payload_length) +\
                                 sizeof(ctx->next_header) + sizeof(ctx->hop_limit) +\
                                 sizeof(ctx->src_addr) + sizeof(ctx->dest_addr) )

unsigned char *macgonuts_make_ip6_pkt(const struct macgonuts_ip6hdr_ctx *ip6hdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    unsigned char *p = NULL;
    if (ip6hdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = IP6_HDR_BASE_SIZE(ip6hdr) + ip6hdr->payload_length;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        *pkt_size = 0;
        return NULL;
    }

    pkt[0] = ip6hdr->version << 4 | ip6hdr->priority;
    pkt[1] = (ip6hdr->flow_label >> 24) & 0xFF;
    pkt[2] = (ip6hdr->flow_label >> 16) & 0xFF;
    pkt[3] = ip6hdr->flow_label & 0xFF;
    pkt[4] = (ip6hdr->payload_length >> 8) & 0xFF;
    pkt[5] = ip6hdr->payload_length & 0xFF;
    pkt[6] = ip6hdr->next_header;
    pkt[7] = ip6hdr->hop_limit;
    p = &pkt[8];
    memcpy(p, &ip6hdr->src_addr[0], sizeof(ip6hdr->src_addr));
    p += sizeof(ip6hdr->src_addr);
    memcpy(p, &ip6hdr->dest_addr[0], sizeof(ip6hdr->dest_addr));
    p += sizeof(ip6hdr->dest_addr);
    if (ip6hdr->payload_length > 0 && ip6hdr->payload != NULL) {
        memcpy(p, ip6hdr->payload, ip6hdr->payload_length);
    }

    return pkt;
}

int macgonuts_read_ip6_pkt(struct macgonuts_ip6hdr_ctx *ip6hdr, const unsigned char *ip6buf, const size_t ip6buf_size) {
    const unsigned char *bp = NULL;
    if (ip6hdr == NULL || ip6buf == NULL) {
        return EINVAL;
    }

    if (ip6buf_size < IP6_HDR_BASE_SIZE(ip6hdr)) {
        return EPROTO;
    }

    bp = ip6buf;

    ip6hdr->version = bp[0] >> 4;
    ip6hdr->priority = bp[0] & 0x0F;
    ip6hdr->flow_label = (uint32_t)bp[1] << 24 | (uint32_t)bp[2] << 16 | (uint32_t)bp[3];
    ip6hdr->payload_length = (uint16_t)bp[4] << 8 | (uint16_t)bp[5];
    ip6hdr->next_header = bp[6];
    ip6hdr->hop_limit = bp[7];
    memcpy(&ip6hdr->src_addr[0], &bp[8], sizeof(ip6hdr->src_addr));
    bp += 8 + sizeof(ip6hdr->src_addr);
    memcpy(&ip6hdr->dest_addr[0], &bp[0], sizeof(ip6hdr->dest_addr));
    bp += sizeof(ip6hdr->dest_addr);
    if (ip6hdr->payload_length > 0) {
        ip6hdr->payload = (unsigned char *)malloc(ip6hdr->payload_length);
        if (ip6hdr->payload == NULL) {
            memset(ip6hdr, 0, sizeof(struct macgonuts_ip6hdr_ctx));
            return ENOMEM;
        }
        memcpy(&ip6hdr->payload[0], bp, ip6hdr->payload_length);
    } else {
        ip6hdr->payload = NULL;
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_ip6hdr(struct macgonuts_ip6hdr_ctx *ip6hdr) {
    if (ip6hdr == NULL) {
        return;
    }
    if (ip6hdr->payload != NULL) {
        free(ip6hdr->payload);
        ip6hdr->payload_length = 0;
        ip6hdr->payload = NULL;
    }
}

#undef IP6_HDR_BASE_SIZE

