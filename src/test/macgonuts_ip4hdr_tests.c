/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ip4hdr_tests.h"
#include <macgonuts_ip4hdr.h>

CUTE_TEST_CASE(macgonuts_read_ip4_pkt_tests)
    unsigned char dgram_from_wire[] = { 0x45, 0x00, 0x00, 0x38,
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
    const size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_ip4hdr_ctx ip4hdr = { 0 };
    CUTE_ASSERT(macgonuts_read_ip4_pkt(NULL, dgram_from_wire, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ip4_pkt(&ip4hdr, NULL, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ip4_pkt(&ip4hdr, dgram_from_wire, 0) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ip4_pkt(&ip4hdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(ip4hdr.version == 4);
    CUTE_ASSERT(ip4hdr.ihl == 5);
    CUTE_ASSERT(ip4hdr.tos == 0x00);
    CUTE_ASSERT(ip4hdr.tlen == 0x0038);
    CUTE_ASSERT(ip4hdr.id == 0xDB08);
    CUTE_ASSERT(ip4hdr.flag_off == 0x4000);
    CUTE_ASSERT(ip4hdr.ttl == 0x40);
    CUTE_ASSERT(ip4hdr.proto == 0x11);
    CUTE_ASSERT(ip4hdr.chsum == 0x8DF4);
    CUTE_ASSERT(ip4hdr.src_addr == 0x0A00020F);
    CUTE_ASSERT(ip4hdr.dest_addr == 0xC0A80501);
    CUTE_ASSERT(ip4hdr.options_size == 0);
    CUTE_ASSERT(ip4hdr.options == NULL);
    CUTE_ASSERT(ip4hdr.payload_size == 36);
    CUTE_ASSERT(memcmp(&ip4hdr.payload[0], &dgram_from_wire[20], ip4hdr.payload_size) == 0);
    macgonuts_release_ip4hdr(&ip4hdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_ip4_pkt_tests)
    unsigned char dgram_from_wire[] = { 0x45, 0x00, 0x00, 0x38,
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
    const size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_ip4hdr_ctx ip4hdr = { 0 };
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;
    CUTE_ASSERT(macgonuts_read_ip4_pkt(&ip4hdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_make_ip4_pkt(NULL, &pkt_size, 0) == NULL);
    CUTE_ASSERT(macgonuts_make_ip4_pkt(&ip4hdr, NULL, 0) == NULL);
    pkt = macgonuts_make_ip4_pkt(&ip4hdr, &pkt_size, 0);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
    ip4hdr.chsum = 0xABCD;
    pkt = macgonuts_make_ip4_pkt(&ip4hdr, &pkt_size, 1);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
    macgonuts_release_ip4hdr(&ip4hdr);
CUTE_TEST_CASE_END
