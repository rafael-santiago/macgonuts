/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_pcap_tests.h"
#include <macgonuts_pcap.h>

static int has_tcpdump(void);

CUTE_TEST_CASE(macgonuts_pcap_tests)
    const unsigned char frame_from_wire6[] = { // INFO(Rafael): Ethernet frame.
                                               0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
                                               0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
                                               0x86, 0xDD,
                                               // INFO(Rafael): IP6 datagram.
                                               0x60, 0x00, 0x00, 0x00, 0x00, 0x20,
                                               0x3A, 0xFF, 0x20, 0x01, 0xCA, 0xFE,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                               0xBA, 0xBA, 0xCA, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                               0xFF, 0x00, 0x00, 0x03,
                                               // INFO(Rafael): ICMP datagram.
                                               0x87, 0x00, 0x18, 0x82, 0x00, 0x00,
                                               0x00, 0x00, 0x20, 0x01, 0xCA, 0xFE,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                                               0x01, 0x01, 0x08, 0x00, 0x27, 0x5D,
                                               0x5B, 0xB8 };
    const unsigned char frame_from_wire4[] = { // INFO(Rafael): Ethernet frame.
                                               0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
                                               0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
                                               0x08, 0x00,
                                               // INFO(Rafael): IP4 datagram.
                                               0x45, 0x00, 0x00, 0x38,
                                               0xDB, 0x08, 0x40, 0x00,
                                               0x40, 0x11, 0x8D, 0xF4,
                                               0x0A, 0x00, 0x02, 0x0F,
                                               0xC0, 0xA8, 0x05, 0x01,
                                               0x9F, 0xC3, 0x00, 0x35,
                                               0x00, 0x24, 0xD1, 0xED,
                                               0x35, 0x8F, 0x01, 0x00,
                                               0x00, 0x01, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x06, 0x67, 0x6F, 0x6F,
                                               0x67, 0x6C, 0x65, 0x03,
                                               0x63, 0x6F, 0x6D, 0x00,
                                               0x00, 0x1C, 0x00, 0x01 };
    FILE *pcapfile = NULL;
    char *data = NULL, *next_data = NULL;
    struct stat st = { 0 };
    if (has_tcpdump()) {
        remove("test.pcap");
        pcapfile = macgonuts_pcapfile_open("test.pcap");
        CUTE_ASSERT(pcapfile != NULL);
        CUTE_ASSERT(macgonuts_pcapfile_write(pcapfile, &frame_from_wire4[0], sizeof(frame_from_wire4)) == EXIT_SUCCESS);
        macgonuts_pcapfile_close(pcapfile);
        CUTE_ASSERT(system("tcpdump -r test.pcap --immediate-mode > tcpdump-out.txt") == 0);
        CUTE_ASSERT(stat("tcpdump-out.txt", &st) == 0);
        data = (char *)malloc(st.st_size);
        CUTE_ASSERT(data != NULL);
        pcapfile = fopen("tcpdump-out.txt", "rb");
        fread(&data[0], st.st_size, 1, pcapfile);
        fclose(pcapfile);
        remove("tcpdump-out.txt");
        CUTE_ASSERT(strstr(data, "10.0.2.15.40899 > 192.168.5.1.domain") != NULL);
        free(data);
        pcapfile = macgonuts_pcapfile_open("test.pcap");
        CUTE_ASSERT(macgonuts_pcapfile_write(pcapfile, &frame_from_wire6[0], sizeof(frame_from_wire6)) == EXIT_SUCCESS);
        macgonuts_pcapfile_close(pcapfile);
        CUTE_ASSERT(system("tcpdump -r test.pcap --immediate-mode > tcpdump-out.txt") == 0);
        remove("test.pcap");
        CUTE_ASSERT(stat("tcpdump-out.txt", &st) == 0);
        data = (char *)malloc(st.st_size);
        CUTE_ASSERT(data != NULL);
        pcapfile = fopen("tcpdump-out.txt", "rb");
        fread(&data[0], st.st_size, 1, pcapfile);
        fclose(pcapfile);
        remove("tcpdump-out.txt");
        next_data = strstr(data, "10.0.2.15.40899 > 192.168.5.1.domain");
        CUTE_ASSERT(next_data != NULL);
        CUTE_ASSERT(strstr(next_data, "IP6 2001:cafe::2 > baba:ca00::1:ff00:3: ICMP6, neighbor solicitation") != NULL);
        free(data);
    } else {
        fprintf(stderr, "skipped: unable to run test because your system does not have tcpdump.\n");
    }
CUTE_TEST_CASE_END

static int has_tcpdump(void) {
    return (system("tcpdump --version >/dev/null 2>&1") == 0);
}
