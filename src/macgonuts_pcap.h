/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_MACGONUTS_PCAP_H
#define MACGONUTS_MACGONUTS_PCAP_H 1

#include <macgonuts_types.h>

FILE *macgonuts_pcapfile_open(const char *filepath);

int macgonuts_pcapfile_write(FILE *pcapfile, const unsigned char *ethfrm, const size_t ethfrm_size);

void macgonuts_pcapfile_close(FILE *pcapfile);

#endif // MACGONUTS_MACGONUTS_PCAP_H
