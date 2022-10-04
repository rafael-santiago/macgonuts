/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ndphdr_tests.h"
#include <macgonuts_ndphdr.h>

CUTE_TEST_CASE(macgonuts_read_ndp_nsna_pkt_tests)
    const unsigned char dgram_from_wire[] = {  // INFO(Rafael): NDP datagram.
                                               0x00, 0x00, 0x00, 0x00,
                                               0x20, 0x01, 0xCA, 0xFE,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x03,
                                               0x01, 0x01, 0x08, 0x00,
                                               0x27, 0x5D, 0x5B, 0xB8 };
    const size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_ndp_nsna_hdr_ctx ndp_nsna_hdr = { 0 };
    CUTE_ASSERT(macgonuts_read_ndp_nsna_pkt(NULL, dgram_from_wire, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ndp_nsna_pkt(&ndp_nsna_hdr, NULL, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ndp_nsna_pkt(&ndp_nsna_hdr, dgram_from_wire, 19) == EPROTO);
    CUTE_ASSERT(macgonuts_read_ndp_nsna_pkt(&ndp_nsna_hdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(ndp_nsna_hdr.reserv == 0x0);
    CUTE_ASSERT(memcmp(&ndp_nsna_hdr.target_addr[0], &dgram_from_wire[4], sizeof(ndp_nsna_hdr.target_addr)) == 0);
    CUTE_ASSERT(ndp_nsna_hdr.options != NULL);
    CUTE_ASSERT(ndp_nsna_hdr.options_size == (dgram_from_wire_size - sizeof(ndp_nsna_hdr.reserv) -
                                              sizeof(ndp_nsna_hdr.target_addr)));
    CUTE_ASSERT(memcmp(&ndp_nsna_hdr.options[0], &dgram_from_wire[sizeof(ndp_nsna_hdr.reserv) +
                                                                  sizeof(ndp_nsna_hdr.target_addr)],
                       ndp_nsna_hdr.options_size) == 0);
    macgonuts_release_ndp_nsna_hdr(&ndp_nsna_hdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_ndp_nsna_pkt_tests)
    const unsigned char dgram_from_wire[] = {  // INFO(Rafael): NDP datagram.
                                               0x00, 0x00, 0x00, 0x00,
                                               0x20, 0x01, 0xCA, 0xFE,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x03,
                                               0x01, 0x01, 0x08, 0x00,
                                               0x27, 0x5D, 0x5B, 0xB8 };
    const size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_ndp_nsna_hdr_ctx ndp_nsna_hdr = { 0 };
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;
    CUTE_ASSERT(macgonuts_make_ndp_nsna_pkt(NULL, &pkt_size) == NULL);
    CUTE_ASSERT(macgonuts_make_ndp_nsna_pkt(&ndp_nsna_hdr, NULL) == NULL);
    CUTE_ASSERT(macgonuts_read_ndp_nsna_pkt(&ndp_nsna_hdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    pkt = macgonuts_make_ndp_nsna_pkt(&ndp_nsna_hdr, &pkt_size);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
    macgonuts_release_ndp_nsna_hdr(&ndp_nsna_hdr);
CUTE_TEST_CASE_END
