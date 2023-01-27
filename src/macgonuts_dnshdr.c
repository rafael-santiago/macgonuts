/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_dnshdr.h>

#define DNS_HDR_BASE_SIZE(c) (sizeof((c)->id) + 2 + sizeof((c)->qdcount) +\
                              sizeof((c)->ancount) + sizeof((c)->nscount) + sizeof((c)->arcount))

unsigned char *macgonuts_make_dns_pkt(const struct macgonuts_dnshdr_ctx *dnshdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    if (dnshdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = DNS_HDR_BASE_SIZE(dnshdr) + dnshdr->rr_size;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        *pkt_size = 0;
        return NULL;
    }

    pkt[ 0] = (dnshdr->id >> 8) & 0xFF;
    pkt[ 1] = dnshdr->id & 0xFF;
    pkt[ 2] = ((uint8_t)(dnshdr->qr & 1) << 7)        |
              ((uint8_t)(dnshdr->opcode & 0x0F) << 6) |
              ((uint8_t)(dnshdr->aa & 1) << 2)        |
              ((uint8_t)(dnshdr->tc & 1) << 1)        |
              ((uint8_t)(dnshdr->rd & 1));
    pkt[ 3] = ((uint8_t)(dnshdr->ra & 1) <<  7)       |
              ((uint8_t)(dnshdr->z & 0x0F) << 6)      |
              ((uint8_t)(dnshdr->rcode & 0x0F));
    pkt[ 4] = (dnshdr->qdcount >> 8) & 0xFF;
    pkt[ 5] = dnshdr->qdcount & 0xFF;
    pkt[ 6] = (dnshdr->ancount >> 8) & 0xFF;
    pkt[ 7] = dnshdr->ancount & 0xFF;
    pkt[ 8] = (dnshdr->nscount >> 8) & 0xFF;
    pkt[ 9] = dnshdr->nscount & 0xFF;
    pkt[10] = (dnshdr->arcount >> 8) & 0xFF;
    pkt[11] = dnshdr->arcount & 0xFF;

    if (dnshdr->rr_size > 0 && dnshdr->rr != NULL) {
        memcpy(&pkt[12], dnshdr->rr, dnshdr->rr_size);
    }

    return pkt;
}

int macgonuts_read_dns_pkt(struct macgonuts_dnshdr_ctx *dnshdr, const unsigned char *dnsbuf, const size_t dnsbuf_size) {
    if (dnshdr == NULL
        || dnsbuf == NULL) {
        return EINVAL;
    }

    if (dnsbuf_size < DNS_HDR_BASE_SIZE(dnshdr)) {
        return EPROTO;
    }

    dnshdr->id = (uint16_t)dnsbuf[0] << 8 | (uint16_t)dnsbuf[1];

    dnshdr->qr = (dnsbuf[2] >> 7) & 1;
    dnshdr->opcode = (dnsbuf[2] >> 3) & 0x0F;
    dnshdr->aa = (dnsbuf[2] >> 2) & 1;
    dnshdr->tc = (dnsbuf[2] >> 1) & 1;
    dnshdr->rd = dnsbuf[2] & 1;
    dnshdr->ra = (dnsbuf[3] >> 7) & 1;
    dnshdr->z = (dnsbuf[3] >> 4) & 7;
    dnshdr->rcode = dnsbuf[3] & 0x0F;

    dnshdr->qdcount = (uint16_t)dnsbuf[ 4] << 8 | (uint16_t)dnsbuf[ 5];
    dnshdr->ancount = (uint16_t)dnsbuf[ 6] << 8 | (uint16_t)dnsbuf[ 7];
    dnshdr->nscount = (uint16_t)dnsbuf[ 8] << 8 | (uint16_t)dnsbuf[ 9];
    dnshdr->arcount = (uint16_t)dnsbuf[10] << 8 | (uint16_t)dnsbuf[11];

    dnshdr->rr_size = dnsbuf_size - DNS_HDR_BASE_SIZE(dnshdr);
    if (dnshdr->rr_size > 0) {
        dnshdr->rr = (uint8_t *)malloc(dnshdr->rr_size);
        if (dnshdr->rr == NULL) {
            memset(dnshdr, 0, sizeof(struct macgonuts_dnshdr_ctx));
            return ENOMEM;
        }
        memcpy(dnshdr->rr, &dnsbuf[12], dnshdr->rr_size);
    }

    return EXIT_SUCCESS;
}

int macgonuts_read_dns_resource_record(struct macgonuts_dns_rr_hdr_ctx *dnsrr,
                                       const struct macgonuts_dnshdr_ctx *dnshdr) {
    return EXIT_FAILURE;
}

uint8_t *macgonuts_make_dns_an_pkt(const char *domain_name, const uint8_t *proto_addr, const size_t proto_addr_size) {
    return NULL;
}

void macgonuts_release_dnshdr(struct macgonuts_dnshdr_ctx *dnshdr) {
    if (dnshdr == NULL) {
        return;
    }
    if (dnshdr->rr != NULL) {
        free(dnshdr->rr);
    }
}

void macgonuts_release_dns_rr_hdr(struct macgonuts_dns_rr_hdr_ctx *dnsrr) {
    struct macgonuts_dns_rr_hdr_ctx *p = NULL, *t = NULL;

    if (dnsrr == NULL) {
        return;
    }

    for (p = t = dnsrr; t != NULL; p = t) {
        t = p->next;
        if (p->name != NULL) {
            free(p->name);
        }
        if (p->rdata != NULL) {
            free(p->rdata);
        }
        if (p != dnsrr) {
            // INFO(Rafael): The first one is stack based, the follow ones are heap based.
            free(p);
        }
    }
}

#undef DNS_HDR_BASE_SIZE
