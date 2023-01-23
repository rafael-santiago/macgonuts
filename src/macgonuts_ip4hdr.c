/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ip4hdr.h>
#include <macgonuts_ipchsum.h>

#define IP4_HDR_BASE_SIZE(c) (1 + sizeof((c)->tos) + sizeof((c)->tlen) + sizeof((c)->id) +\
                              sizeof((c)->flag_off) + sizeof((c)->ttl) + sizeof((c)->proto) +\
                              sizeof((c)->chsum) + sizeof((c)->src_addr) + sizeof((c)->dest_addr))

unsigned char *macgonuts_make_ip4_pkt(const struct macgonuts_ip4hdr_ctx *ip4hdr, size_t *pkt_size,
                                      const int compute_checksum) {
    unsigned char *pkt = NULL;
    uint16_t chsum = 0;

    if (ip4hdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = IP4_HDR_BASE_SIZE(ip4hdr) + ip4hdr->payload_size;
    pkt = (unsigned char *) malloc(*pkt_size);
    if (pkt == NULL) {
        return NULL;
    }

    pkt[ 0] = (ip4hdr->version << 4) | ip4hdr->ihl;
    pkt[ 1] = ip4hdr->tos;
    pkt[ 2] = (ip4hdr->tlen >> 8) & 0xFF;
    pkt[ 3] = ip4hdr->tlen & 0xFF;
    pkt[ 4] = (ip4hdr->id >> 8) & 0xFF;
    pkt[ 5] = ip4hdr->id & 0xFF;
    pkt[ 6] = (ip4hdr->flag_off >> 8) & 0xFF;
    pkt[ 7] = ip4hdr->flag_off & 0xFF;
    pkt[ 8] = ip4hdr->ttl;
    pkt[ 9] = ip4hdr->proto;
    if (!compute_checksum) {
        pkt[10] = (ip4hdr->chsum >> 8) & 0xFF;
        pkt[11] = ip4hdr->chsum & 0xFF;
    }
    pkt[12] = (ip4hdr->src_addr >> 24) & 0xFF;
    pkt[13] = (ip4hdr->src_addr >> 16) & 0xFF;
    pkt[14] = (ip4hdr->src_addr >>  8) & 0xFF;
    pkt[15] = ip4hdr->src_addr & 0xFF;
    pkt[16] = (ip4hdr->dest_addr >> 24) & 0xFF;
    pkt[17] = (ip4hdr->dest_addr >> 16) & 0xFF;
    pkt[18] = (ip4hdr->dest_addr >>  8) & 0xFF;
    pkt[19] = ip4hdr->dest_addr & 0xFF;

    if (compute_checksum) {
        pkt[10] = 0;
        pkt[11] = 0;
        chsum = macgonuts_eval_ipchsum(&pkt[0], 20, NULL, 0);
        pkt[10] = (chsum >> 8) & 0xFF;
        pkt[11] = chsum & 0xFF;
    }

    if (ip4hdr->options != NULL && ip4hdr->options_size > 0) {
        memcpy(&pkt[IP4_HDR_BASE_SIZE(ip4hdr)], ip4hdr->options, ip4hdr->options_size);
    }

    if (ip4hdr->payload != NULL && ip4hdr->payload_size > 0) {
        memcpy(&pkt[IP4_HDR_BASE_SIZE(ip4hdr) + ip4hdr->options_size], ip4hdr->payload, ip4hdr->payload_size);
    }

    return pkt;
}

int macgonuts_read_ip4_pkt(struct macgonuts_ip4hdr_ctx *ip4hdr, const unsigned char *ip4buf, const size_t ip4buf_size) {
    if (ip4hdr == NULL || ip4buf == NULL) {
        return EINVAL;
    }

    if (ip4buf_size < IP4_HDR_BASE_SIZE(ip4hdr)) {
        return EPROTO;
    }

    ip4hdr->version = ip4buf[0] >> 4;
    ip4hdr->ihl = ip4buf[0] & 0x0F;
    ip4hdr->tos = ip4buf[1];
    ip4hdr->tlen = (uint16_t)ip4buf[2] << 8 | (uint16_t)ip4buf[3];
    ip4hdr->id = (uint16_t)ip4buf[4] << 8 | (uint16_t)ip4buf[5];
    ip4hdr->flag_off = (uint16_t)ip4buf[6] << 8 | (uint16_t)ip4buf[7];
    ip4hdr->ttl = ip4buf[8];
    ip4hdr->proto = ip4buf[9];
    ip4hdr->chsum = (uint16_t)ip4buf[10] << 8 | (uint16_t)ip4buf[11];
    ip4hdr->src_addr = (uint32_t)ip4buf[12] << 24 |
                       (uint32_t)ip4buf[13] << 16 |
                       (uint32_t)ip4buf[14] <<  8 |
                       (uint32_t)ip4buf[15];
    ip4hdr->dest_addr = (uint32_t)ip4buf[16] << 24 |
                        (uint32_t)ip4buf[17] << 16 |
                        (uint32_t)ip4buf[18] <<  8 |
                        (uint32_t)ip4buf[19];

    ip4hdr->options_size = (ip4hdr->ihl << 2) - IP4_HDR_BASE_SIZE(ip4hdr);
    if (ip4hdr->options_size > 0) {
        ip4hdr->options = (uint8_t *)malloc(ip4hdr->options_size);
        if (ip4hdr->options == NULL) {
            ip4hdr->options_size = 0;
            return ENOMEM;
        }
        memcpy(&ip4hdr->options[0], &ip4buf[IP4_HDR_BASE_SIZE(ip4hdr)], ip4buf_size - IP4_HDR_BASE_SIZE(ip4hdr));
    }

    ip4hdr->payload_size = ip4buf_size - IP4_HDR_BASE_SIZE(ip4hdr) - ip4hdr->options_size;
    if (ip4hdr->payload_size > 0) {
        ip4hdr->payload = (uint8_t *)malloc(ip4hdr->payload_size);
        if (ip4hdr->payload == NULL) {
            macgonuts_release_ip4hdr(ip4hdr);
            return ENOMEM;
        }
        memcpy(&ip4hdr->payload[0], &ip4buf[IP4_HDR_BASE_SIZE(ip4hdr) + ip4hdr->options_size], ip4hdr->payload_size);
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_ip4hdr(struct macgonuts_ip4hdr_ctx *ip4hdr) {
    if (ip4hdr == NULL) {
        return;
    }
    if (ip4hdr->options != NULL) {
        free(ip4hdr->options);
        ip4hdr->options = NULL;
        ip4hdr->options_size = 0;
    }
    if (ip4hdr->payload != NULL) {
        free(ip4hdr->payload);
        ip4hdr->payload = NULL;
        ip4hdr->payload_size = 0;
    }
}

#undef IP4_HDR_BASE_SIZE
