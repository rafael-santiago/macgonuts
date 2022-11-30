/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_printpkt.h>

void macgonuts_printpkt(FILE *pktout, const unsigned char *pkt, const size_t pkt_size) {
    const char *p = pkt, *lp = pkt, *np = pkt;
    const char *p_end = p + pkt_size;
    size_t off = 0;
    size_t o = 0;
    if (pkt == NULL || pkt_size == 0) {
        return;
    }
    while (p != p_end) {
        fprintf(pktout, "0x%.4x:  ", off);
        for (o = 0; o < 16; o++) {
            if (p != p_end) {
                fprintf(pktout, "%.2x", *p++);
                if (p != p_end) {
                    fprintf(pktout, "%.2x ", *p++);
                }
            } else {
                fprintf(pktout, "     ");
            }
            if (o == 15) {
                np = p;
                p = lp;
                while (p != np) {
                    fprintf(pktout, "%c", (isprint(*p)) ? *p : '.');
                    p++;
                }
                lp = np;
            }
        }
        fprintf(pktout, "\n");
        off += 16;
    }
}

