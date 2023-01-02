/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_arphdr.h>
#include <macgonuts_status_info.h>

#define ARP_HDR_BASE_SIZE(ctx) (sizeof(ctx->htype) + sizeof(ctx->ptype) +\
                                sizeof(ctx->hlen) + sizeof(ctx->plen) +\
                                sizeof(ctx->oper))

unsigned char *macgonuts_make_arp_pkt(const struct macgonuts_arphdr_ctx *arphdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    unsigned char *p = NULL;

    if (arphdr == NULL || pkt_size == NULL
        || arphdr->sha == NULL || arphdr->spa == NULL
        || arphdr->tha == NULL || arphdr->tpa == NULL) {
        return NULL;
    }

    *pkt_size = ARP_HDR_BASE_SIZE(arphdr) + ((arphdr->hlen + arphdr->plen) << 1);
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        macgonuts_si_error("%s", strerror(errno));
        *pkt_size = 0;
        return NULL;
    }

    pkt[0] = arphdr->htype >> 8;
    pkt[1] = arphdr->htype & 0xFF;
    pkt[2] = arphdr->ptype >> 8;
    pkt[3] = arphdr->ptype & 0xFF;
    pkt[4] = arphdr->hlen;
    pkt[5] = arphdr->plen;
    pkt[6] = arphdr->oper >> 8;
    pkt[7] = arphdr->oper & 0xFF;

    p = &pkt[8];
    memcpy(p, arphdr->sha, arphdr->hlen);
    p += arphdr->hlen;
    memcpy(p, arphdr->spa, arphdr->plen);
    p += arphdr->plen;
    memcpy(p, arphdr->tha, arphdr->hlen);
    p += arphdr->hlen;
    memcpy(p, arphdr->tpa, arphdr->plen);

    return pkt;
}

int macgonuts_read_arp_pkt(struct macgonuts_arphdr_ctx *arphdr, const unsigned char *arpbuf, const size_t arpbuf_size) {
    const unsigned char *ap = NULL;
    int err = EFAULT;

    if (arphdr == NULL || arpbuf == NULL) {
        err = EINVAL;
        goto macgonuts_read_arp_pkt_epilogue;
    }

    memset(arphdr, 0, sizeof(struct macgonuts_arphdr_ctx));

    if (arpbuf_size < ARP_HDR_BASE_SIZE(arphdr)) {
        err = EPROTO;
        goto macgonuts_read_arp_pkt_epilogue;
    }

    arphdr->htype = (uint16_t)arpbuf[0] << 8 | (uint16_t)arpbuf[1];
    arphdr->ptype = (uint16_t)arpbuf[2] << 8 | (uint16_t)arpbuf[3];
    arphdr->hlen = arpbuf[4];
    arphdr->plen = arpbuf[5];
    arphdr->oper = (uint16_t)arpbuf[6] << 8 | (uint16_t)arpbuf[7];

    if ((arpbuf_size - ARP_HDR_BASE_SIZE(arphdr))  < ((arphdr->hlen + arphdr->plen) << 1)) {
        err = EPROTO;
        goto macgonuts_read_arp_pkt_epilogue;
    }

    ap = &arpbuf[8];

    arphdr->sha = (uint8_t *)malloc(arphdr->hlen);
    if (arphdr->sha == NULL) {
        err = ENOMEM;
        goto macgonuts_read_arp_pkt_epilogue;
    }
    memcpy(arphdr->sha, ap, arphdr->hlen);
    ap += arphdr->hlen;

    arphdr->spa = (uint8_t *)malloc(arphdr->plen);
    if (arphdr->spa == NULL) {
        err = ENOMEM;
        goto macgonuts_read_arp_pkt_epilogue;
    }
    memcpy(arphdr->spa, ap, arphdr->plen);
    ap += arphdr->plen;

    arphdr->tha = (uint8_t *)malloc(arphdr->hlen);
    if (arphdr->tha == NULL) {
        err = ENOMEM;
        goto macgonuts_read_arp_pkt_epilogue;
    }
    memcpy(arphdr->tha, ap, arphdr->hlen);
    ap += arphdr->hlen;

    arphdr->tpa = (uint8_t *)malloc(arphdr->plen);
    if (arphdr->tpa == NULL) {
        err = ENOMEM;
        goto macgonuts_read_arp_pkt_epilogue;
    }
    memcpy(arphdr->tpa, ap, arphdr->plen);
    ap += arphdr->plen;

    err = EXIT_SUCCESS;

macgonuts_read_arp_pkt_epilogue:

    if (arphdr != NULL && err != EXIT_SUCCESS) {
        macgonuts_release_arphdr(arphdr);
    }

    return err;
}

void macgonuts_release_arphdr(struct macgonuts_arphdr_ctx *arphdr) {
    if (arphdr == NULL) {
        return;
    }
    if (arphdr->sha != NULL) {
        free(arphdr->sha);
        arphdr->sha = NULL;
    }
    if (arphdr->spa != NULL) {
        free(arphdr->spa);
        arphdr->spa = NULL;
    }
    if (arphdr->tha != NULL) {
        free(arphdr->tha);
        arphdr->tha = NULL;
    }
    if (arphdr->tpa != NULL) {
        free(arphdr->tpa);
        arphdr->tpa = NULL;
    }
}

#undef ARP_HDR_BASE_SIZE
