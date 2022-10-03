/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ip6hdr_tests.h"
#include <macgonuts_ip6hdr.h>

CUTE_TEST_CASE(macgonuts_read_ip6_pkt_tests)
    const unsigned char datagram_from_wire[] = { // INFO(Rafael): IP6 datagram.
                                                 0x60, 0x00, 0x00, 0x00, 0x00, 0x20,
                                                 0x3A, 0xFF, 0x20, 0x01, 0xCA, 0xFE,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                                 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                                 0xFF, 0x00, 0x00, 0x03,
                                                 // INFO(Rafael): ICMP datagram.
                                                 0x87, 0x00, 0x18, 0x82, 0x00, 0x00,
                                                 0x00, 0x00, 0x20, 0x01, 0xCA, 0xFE,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                                                 0x01, 0x01, 0x08, 0x00, 0x27, 0x5D,
                                                 0x5B, 0xB8 };
    const size_t datagram_from_wire_size = sizeof(datagram_from_wire) / sizeof(datagram_from_wire[0]);
    struct macgonuts_ip6hdr_ctx ip6hdr = { 0 };
    CUTE_ASSERT(macgonuts_read_ip6_pkt(NULL, datagram_from_wire, datagram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ip6_pkt(&ip6hdr, NULL, datagram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ip6_pkt(&ip6hdr, datagram_from_wire, 20) == EPROTO);
    CUTE_ASSERT(macgonuts_read_ip6_pkt(&ip6hdr, datagram_from_wire, datagram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(ip6hdr.version == 0x06);
    CUTE_ASSERT(ip6hdr.priority == 0x00);
    CUTE_ASSERT(ip6hdr.flow_label == 0x00);
    CUTE_ASSERT(ip6hdr.payload_length == 0x20);
    CUTE_ASSERT(ip6hdr.next_header == 0x3A);
    CUTE_ASSERT(ip6hdr.hop_limit = 0xFF);
    CUTE_ASSERT(memcmp(&ip6hdr.src_addr[0], &datagram_from_wire[8], sizeof(ip6hdr.src_addr)) == 0);
    CUTE_ASSERT(memcmp(&ip6hdr.dest_addr[0], &datagram_from_wire[24], sizeof(ip6hdr.dest_addr)) == 0);
    CUTE_ASSERT(ip6hdr.payload != NULL);
    macgonuts_release_ip6hdr(&ip6hdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_ip6_pkt_tests)
    const unsigned char datagram_from_wire[] = { // INFO(Rafael): IP6 datagram.
                                                 0x60, 0x00, 0x00, 0x00, 0x00, 0x20,
                                                 0x3A, 0xFF, 0x20, 0x01, 0xCA, 0xFE,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                                 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                                 0xFF, 0x00, 0x00, 0x03,
                                                 // INFO(Rafael): ICMP datagram.
                                                 0x87, 0x00, 0x18, 0x82, 0x00, 0x00,
                                                 0x00, 0x00, 0x20, 0x01, 0xCA, 0xFE,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                                                 0x01, 0x01, 0x08, 0x00, 0x27, 0x5D,
                                                 0x5B, 0xB8 };
    const size_t datagram_from_wire_size = sizeof(datagram_from_wire) / sizeof(datagram_from_wire[0]);
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;
    struct macgonuts_ip6hdr_ctx ip6hdr = { 0 };
    CUTE_ASSERT(macgonuts_make_ip6_pkt(NULL, &pkt_size) == NULL);
    CUTE_ASSERT(macgonuts_make_ip6_pkt(&ip6hdr, NULL) == 0);
    CUTE_ASSERT(macgonuts_read_ip6_pkt(&ip6hdr, datagram_from_wire, datagram_from_wire_size) == EXIT_SUCCESS);
    pkt = macgonuts_make_ip6_pkt(&ip6hdr, &pkt_size);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == datagram_from_wire_size);
    CUTE_ASSERT(memcmp(pkt, datagram_from_wire, pkt_size) == 0);
    free(pkt);
    macgonuts_release_ip6hdr(&ip6hdr);
CUTE_TEST_CASE_END
