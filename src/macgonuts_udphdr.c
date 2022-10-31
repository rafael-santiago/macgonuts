/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_udphdr.h>
#include <macgonuts_ipchsum.h>

#define UDP_HDR_BASE_SIZE(c) ( sizeof((c)->src_port) +\
                               sizeof((c)->dest_port) +\
                               sizeof((c)->len) +\
                               sizeof((c)->chsum) )

unsigned char *macgonuts_make_udp_pkt(const struct macgonuts_udphdr_ctx *udphdr, size_t *pkt_size,
                                      const void *pheader, const size_t pheader_size) {
    unsigned char *pkt = NULL;
    uint16_t chsum = 0;

    if (udphdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = UDP_HDR_BASE_SIZE(udphdr) + udphdr->payload_size;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        *pkt_size = 0;
        return NULL;
    }

    pkt[0] = (udphdr->src_port >> 8) & 0xFF;
    pkt[1] = udphdr->src_port & 0xFF;
    pkt[2] = (udphdr->dest_port >> 8) & 0xFF;
    pkt[3] = udphdr->dest_port & 0xFF;
    pkt[4] = (udphdr->len >> 8) & 0xFF;
    pkt[5] = udphdr->len & 0xFF;
    if (pheader == NULL) {
        pkt[6] = (udphdr->chsum >> 8) & 0xFF;
        pkt[7] = udphdr->chsum & 0xFF;
    }

    if (udphdr->payload != NULL && udphdr->payload_size > 0) {
        memcpy(&pkt[UDP_HDR_BASE_SIZE(udphdr)], udphdr->payload, udphdr->payload_size);
    }

    if (pheader != NULL) {
        pkt[6] = 0;
        pkt[7] = 0;
        chsum = macgonuts_eval_ipchsum(&pkt[0], *pkt_size, (unsigned char *)pheader, pheader_size);
        pkt[6] = (chsum >> 8) & 0xFF;
        pkt[7] = chsum & 0xFF;
    }

    return pkt;
}

int macgonuts_read_udp_pkt(struct macgonuts_udphdr_ctx *udphdr, const unsigned char *udpbuf, const size_t udpbuf_size) {
    if (udphdr == NULL || udpbuf == NULL || udpbuf_size == 0) {
        return EINVAL;
    }

    udphdr->src_port = (uint16_t)udpbuf[0] << 8 | (uint16_t)udpbuf[1];
    udphdr->dest_port = (uint16_t)udpbuf[2] << 8 | (uint16_t)udpbuf[3];
    udphdr->len = (uint16_t)udpbuf[4] << 8 | (uint16_t)udpbuf[5];
    udphdr->chsum = (uint16_t)udpbuf[6] << 8 | (uint16_t)udpbuf[7];

    udphdr->payload_size = udpbuf_size - UDP_HDR_BASE_SIZE(udphdr);
    if (udphdr->payload_size > 0) {
        udphdr->payload = (uint8_t *)malloc(udphdr->payload_size);
        if (udphdr->payload == NULL) {
            return ENOMEM;
        }
        memcpy(&udphdr->payload[0], &udpbuf[UDP_HDR_BASE_SIZE(udphdr)], udphdr->payload_size);
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_udphdr(struct macgonuts_udphdr_ctx *udphdr) {
    if (udphdr == NULL) {
        return;
    }
    if (udphdr->payload != NULL) {
        free(udphdr->payload);
        udphdr->payload = NULL;
        udphdr->payload_size = 0;
    }
}

#undef UDP_HDR_BASE_SIZE
