/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_PRINTPKT_H
#define MACGONUTS_CMD_MACGONUTS_PRINTPKT_H 1

#include <macgonuts_types.h>

void macgonuts_printpkt(FILE *pktout, const unsigned char *pkt, const size_t pkt_size);

#endif // MACGONUTS_CMD_MACGONUTS_PRINTPKT_H
