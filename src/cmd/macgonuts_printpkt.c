/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_printpkt.h>
#include <macgonuts_pcap.h>
#include <macgonuts_thread.h>

static macgonuts_mutex_t g_PrintPktGiantLock = MACGONUTS_DEFAULT_MUTEX_INITIALIZER;

int macgonuts_printpkt(FILE *pktout, const unsigned char *pkt, const size_t pkt_size) {
    const unsigned char *p = pkt, *lp = pkt, *np = pkt;
    const unsigned char *p_end = p + pkt_size;
    size_t off = 0;
    size_t o = 0;
    int err = EFAULT;
    macgonuts_mutex_lock(&g_PrintPktGiantLock);
    if (pkt == NULL || pkt_size == 0) {
        err = EINVAL;
        goto macgonuts_printpkt_epilogue;
    }
    err = fprintf(pktout, "\n");
    if (err < 0) {
        return err;
    }
    while (p != p_end) {
        err = fprintf(pktout, "0x%.4x:  ", off);
        if (err < 0) {
            goto macgonuts_printpkt_epilogue;
        }
        for (o = 0; o < 8; o++) {
            if (p != p_end) {
                err = fprintf(pktout, "%.2x", *p++);
                if (err < 0) {
                    goto macgonuts_printpkt_epilogue;
                }
                if (p != p_end) {
                    err = fprintf(pktout, "%.2x ", *p++);
                    if (err < 0) {
                        goto macgonuts_printpkt_epilogue;
                    }
                }
            } else {
                err = fprintf(pktout, "     ");
                if (err < 0) {
                    goto macgonuts_printpkt_epilogue;
                }
            }
            if (o == 7) {
                np = p;
                p = lp;
                while (p != np) {
                    err = fprintf(pktout, "%c", (isprint(*p)) ? *p : '.');
                    if (err < 0) {
                        goto macgonuts_printpkt_epilogue;
                    }
                    p++;
                }
                lp = np;
            }
        }
        err = fprintf(pktout, "\n");
        if (err < 0) {
            goto macgonuts_printpkt_epilogue;
        }
        off += 16;
    }

    err = fprintf(pktout, "_________________________________________________________________\n");

macgonuts_printpkt_epilogue:
    macgonuts_mutex_unlock(&g_PrintPktGiantLock);

    return err;
}

int macgonuts_printpkt2pcap(FILE *pcapfile, const unsigned char *pkt, const size_t pkt_size) {
    int err = EFAULT;
    macgonuts_mutex_lock(&g_PrintPktGiantLock);
    err = macgonuts_pcapfile_write(pcapfile, pkt, pkt_size);
    macgonuts_mutex_unlock(&g_PrintPktGiantLock);
    return err;
}
