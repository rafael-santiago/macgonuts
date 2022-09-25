/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_arphdr.h>

unsigned char *macgonuts_make_arp_pkt(const struct macgonuts_arphdr_ctx *arphdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    unsigned char *p = NULL;

    if (arphdr == NULL || pkt_size == NULL
        || arphdr->sha == NULL || arphdr->spa == NULL
        || arphdr->tha == NULL || arphdr->tpa == NULL) {
        return NULL;
    }

    *pkt_size = 10 + ((arphdr->hlen + arphdr->plen) << 1);
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        perror("malloc()");
        *pkt_size = 0;
        return NULL;
    }

    pkt[0] = arphdr->htype >> 16;
    pkt[1] = arphdr->htype & 0xFF;
    pkt[2] = arphdr->ptype >> 16;
    pkt[3] = arphdr->ptype & 0xFF;
    pkt[4] = arphdr->hlen;
    pkt[5] = arphdr->plen;
    pkt[6] = arphdr->oper >> 16;
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
    const unsigned char *ap = NULL, *ap_end = NULL;
    int err = EFAULT;

    if (arphdr == NULL || arpbuf == NULL || arpbuf_size == 0) {
        err = EINVAL;
        goto macgonuts_read_arp_pkt_epilogue;
    }

    memset(arphdr, 0, sizeof(struct macgonuts_arphdr_ctx));

    if (arpbuf_size < 8) {
        err = EPROTO;
        goto macgonuts_read_arp_pkt_epilogue;
    }

    arphdr->htype = (uint16_t)arpbuf[0] << 16 | (uint16_t)arpbuf[1];
    arphdr->ptype = (uint16_t)arpbuf[2] << 16 | (uint16_t)arpbuf[3];
    arphdr->hlen = arpbuf[4];
    arphdr->plen = arpbuf[5];
    arphdr->oper = (uint16_t)arpbuf[6] << 16 | (uint16_t)arpbuf[7];

    if ((arpbuf_size - 8)  < ((arphdr->hlen + arphdr->plen) << 1)) {
        err = EPROTO;
        goto macgonuts_read_arp_pkt_epilogue;
    }

    ap = &arpbuf[8];
    ap_end = arpbuf + arpbuf_size;

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

    err = (ap == ap_end) ? EXIT_SUCCESS : EPROTO;

macgonuts_read_arp_pkt_epilogue:

    if (err != EXIT_SUCCESS) {
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

    return err;
}