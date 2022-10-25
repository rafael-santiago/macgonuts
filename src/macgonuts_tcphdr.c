/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_tcphdr.h>

#define TCP_HDR_BASE_SIZE(c) ( sizeof((c)->src_port) +\
                               sizeof((c)->dest_port) +\
                               sizeof((c)->seqno) +\
                               sizeof((c)->ackno) +\
                               sizeof((c)->doff_reserv_flags) +\
                               sizeof((c)->window) +\
                               sizeof((c)->chsum) +\
                               sizeof((c)->urgptr) )

unsigned char *macgonuts_make_tcp_pkt(const struct macgonuts_tcphdr_ctx *tcphdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;

    if (tcphdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = TCP_HDR_BASE_SIZE(tcphdr) + tcphdr->options_size + tcphdr->payload_size;
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        *pkt_size = 0;
        return NULL;
    }

    pkt[ 0] = (tcphdr->src_port >> 8) & 0xFF;
    pkt[ 1] = tcphdr->src_port & 0xFF;
    pkt[ 2] = (tcphdr->dest_port >> 8) & 0xFF;
    pkt[ 3] = tcphdr->dest_port & 0xFF;
    pkt[ 4] = (tcphdr->seqno >> 24) & 0xFF;
    pkt[ 5] = (tcphdr->seqno >> 16) & 0xFF;
    pkt[ 6] = (tcphdr->seqno >>  8) & 0xFF;
    pkt[ 7] = tcphdr->seqno & 0xFF;
    pkt[ 8] = (tcphdr->ackno >> 24) & 0xFF;
    pkt[ 9] = (tcphdr->ackno >> 16) & 0xFF;
    pkt[10] = (tcphdr->ackno >> 8) & 0xFF;
    pkt[11] = tcphdr->ackno & 0xFF;
    pkt[12] = (tcphdr->doff_reserv_flags >> 8) & 0xFF;
    pkt[13] = tcphdr->doff_reserv_flags & 0xFF;
    pkt[14] = (tcphdr->window >> 8) & 0xFF;
    pkt[15] = tcphdr->window & 0xFF;
    pkt[16] = (tcphdr->chsum >> 8) & 0xFF;
    pkt[17] = tcphdr->chsum & 0xFF;
    pkt[18] = (tcphdr->urgptr >> 8) & 0xFF;
    pkt[19] = tcphdr->urgptr & 0xFF;

    if (tcphdr->options != NULL && tcphdr->options_size > 0) {
        memcpy(&pkt[TCP_HDR_BASE_SIZE(tcphdr)], tcphdr->options, tcphdr->options_size);
    }

    if (tcphdr->payload != NULL && tcphdr->payload_size > 0) {
        memcpy(&pkt[TCP_HDR_BASE_SIZE(tcphdr) + tcphdr->options_size], tcphdr->payload, tcphdr->payload_size);
    }

    return pkt;
}

int macgonuts_read_tcp_pkt(struct macgonuts_tcphdr_ctx *tcphdr, const unsigned char *tcpbuf, const size_t tcpbuf_size) {
    if (tcphdr == NULL || tcpbuf == NULL || tcpbuf_size == 0) {
        return EINVAL;
    }

    tcphdr->src_port = (uint16_t)tcpbuf[ 0] << 8 | (uint16_t)tcpbuf[ 1];
    tcphdr->dest_port = (uint16_t)tcpbuf[ 2] << 8 | (uint16_t)tcpbuf[ 3];
    tcphdr->seqno = (uint32_t)tcpbuf[ 4] << 24 |
                    (uint32_t)tcpbuf[ 5] << 16 |
                    (uint32_t)tcpbuf[ 6] <<  8 |
                    (uint32_t)tcpbuf[ 7];
    tcphdr->ackno = (uint32_t)tcpbuf[ 8] << 24 |
                    (uint32_t)tcpbuf[ 9] << 16 |
                    (uint32_t)tcpbuf[10] <<  8 |
                    (uint32_t)tcpbuf[11];
    tcphdr->doff_reserv_flags = (uint16_t)tcpbuf[12] << 8 | (uint16_t)tcpbuf[13];
    tcphdr->window = (uint16_t)tcpbuf[14] << 8 | (uint16_t)tcpbuf[15];
    tcphdr->chsum = (uint16_t)tcpbuf[16] << 8 | (uint16_t)tcpbuf[17];
    tcphdr->urgptr = (uint16_t)tcpbuf[18] << 8 | (uint16_t)tcpbuf[19];

    tcphdr->options_size = ((tcphdr->doff_reserv_flags >> 12) << 2) - TCP_HDR_BASE_SIZE(tcphdr);
    if (tcphdr->options_size == 0) {
        tcphdr->options_size = 0;
    } else {
        tcphdr->options = (uint8_t *)malloc(tcphdr->options_size);
        if (tcphdr->options == NULL) {
            return ENOMEM;
        }
        memcpy(tcphdr->options, &tcpbuf[TCP_HDR_BASE_SIZE(tcphdr)], tcphdr->options_size);
    }

    if ((tcpbuf + TCP_HDR_BASE_SIZE(tcphdr) + tcphdr->options_size) != (tcpbuf + tcpbuf_size)) {
        tcphdr->payload_size = tcpbuf_size - TCP_HDR_BASE_SIZE(tcphdr) - tcphdr->options_size;
        tcphdr->payload = (uint8_t *)malloc(tcphdr->payload_size);
        if (tcphdr->payload == NULL) {
            macgonuts_release_tcphdr(tcphdr);
            return ENOMEM;
        }
        memcpy(tcphdr->payload,
               &tcpbuf[TCP_HDR_BASE_SIZE(tcphdr) + tcphdr->options_size],
               tcphdr->payload_size);
    } else {
        tcphdr->payload = NULL;
        tcphdr->payload_size = 0;
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_tcphdr(struct macgonuts_tcphdr_ctx *tcphdr) {
    if (tcphdr == NULL) {
        return;
    }
    if (tcphdr->options != NULL) {
        free(tcphdr->options);
        tcphdr->options = NULL;
        tcphdr->options_size = 0;
    }
    if (tcphdr->payload != NULL) {
        free(tcphdr->payload);
        tcphdr->payload = NULL;
        tcphdr->payload_size = 0;
    }
}

#undef TCP_HDR_BASE_SIZE
