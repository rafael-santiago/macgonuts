/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_icmphdr_tests.h"
#include <macgonuts_icmphdr.h>


CUTE_TEST_CASE(macgonuts_read_icmp_pkt_tests)
    const unsigned char datagram_from_wire[] = { // INFO(Rafael): ICMP datagram.
                                                 0x87, 0x00, 0x18, 0x82, 0x00, 0x00,
                                                 0x00, 0x00, 0x20, 0x01, 0xCA, 0xFE,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                                                 0x01, 0x01, 0x08, 0x00, 0x27, 0x5D,
                                                 0x5B, 0xB8 };
    const size_t datagram_from_wire_size = sizeof(datagram_from_wire) / sizeof(datagram_from_wire[0]);
    struct macgonuts_icmphdr_ctx icmphdr = { 0 };
    CUTE_ASSERT(macgonuts_read_icmp_pkt(NULL, datagram_from_wire, datagram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_icmp_pkt(&icmphdr, NULL, datagram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_icmp_pkt(&icmphdr, datagram_from_wire, 3) == EPROTO);
    CUTE_ASSERT(macgonuts_read_icmp_pkt(&icmphdr, datagram_from_wire, datagram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(icmphdr.type == 0x87);
    CUTE_ASSERT(icmphdr.code == 0x00);
    CUTE_ASSERT(icmphdr.chsum == 0x1882);
    CUTE_ASSERT(icmphdr.payload != NULL);
    CUTE_ASSERT(icmphdr.payload_size == (datagram_from_wire_size - 4));
    macgonuts_release_icmphdr(&icmphdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_icmp_pkt_tests)
    const unsigned char datagram_from_wire[] = { // INFO(Rafael): ICMP datagram.
                                                 0x87, 0x00, 0x18, 0x82, 0x00, 0x00,
                                                 0x00, 0x00, 0x20, 0x01, 0xCA, 0xFE,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                                                 0x01, 0x01, 0x08, 0x00, 0x27, 0x5D,
                                                 0x5B, 0xB8 };
    const size_t datagram_from_wire_size = sizeof(datagram_from_wire) / sizeof(datagram_from_wire[0]);
    struct macgonuts_icmphdr_ctx icmphdr = { 0 };
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;
    CUTE_ASSERT(macgonuts_make_icmp_pkt(NULL, &pkt_size) == NULL);
    CUTE_ASSERT(macgonuts_make_icmp_pkt(&icmphdr, NULL) == NULL);
    CUTE_ASSERT(macgonuts_read_icmp_pkt(&icmphdr, datagram_from_wire, datagram_from_wire_size) == EXIT_SUCCESS);
    pkt = macgonuts_make_icmp_pkt(&icmphdr, &pkt_size);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == datagram_from_wire_size);
    CUTE_ASSERT(memcmp(pkt, datagram_from_wire, pkt_size) == 0);
    macgonuts_release_icmphdr(&icmphdr);
    free(pkt);
CUTE_TEST_CASE_END
