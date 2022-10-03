/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ethfrm_tests.h"
#include <macgonuts_ethfrm.h>

CUTE_TEST_CASE(macgonuts_read_ethernet_frm_tests)
    const unsigned char frame_from_wire[] = { // INFO(Rafael): Ethernet frame.
                                              0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
                                              0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
                                              0x86, 0xDD,
                                              // INFO(Rafael): IP6 datagram.
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
    const size_t frame_from_wire_size = sizeof(frame_from_wire) / sizeof(frame_from_wire[0]);
    struct macgonuts_ethfrm_ctx ethfrm = { 0 };
    CUTE_ASSERT(macgonuts_read_ethernet_frm(NULL, frame_from_wire, frame_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ethernet_frm(&ethfrm, NULL, frame_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_ethernet_frm(&ethfrm, frame_from_wire, 13) == EPROTO);
    CUTE_ASSERT(macgonuts_read_ethernet_frm(&ethfrm, frame_from_wire, frame_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(&ethfrm.dest_hw_addr, &frame_from_wire[0], sizeof(ethfrm.dest_hw_addr)) == 0);
    CUTE_ASSERT(memcmp(&ethfrm.src_hw_addr, &frame_from_wire[6], sizeof(ethfrm.src_hw_addr)) == 0);
    CUTE_ASSERT(ethfrm.ether_type == 0x86DD);
    CUTE_ASSERT(ethfrm.data != NULL);
    CUTE_ASSERT(ethfrm.data_size == (frame_from_wire_size - 14));
    macgonuts_release_ethfrm(&ethfrm);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_ethernet_frm_tests)
    const unsigned char frame_from_wire[] = { // INFO(Rafael): Ethernet frame.
                                              0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
                                              0x08, 0x00, 0x27, 0x5D, 0x5B, 0xB8,
                                              0x86, 0xDD,
                                              // INFO(Rafael): IP6 datagram.
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
    const size_t frame_from_wire_size = sizeof(frame_from_wire) / sizeof(frame_from_wire[0]);
    struct macgonuts_ethfrm_ctx ethfrm = { 0 };
    unsigned char *frm = NULL;
    size_t frm_size = 0;
    CUTE_ASSERT(macgonuts_make_ethernet_frm(NULL, &frm_size) == NULL);
    CUTE_ASSERT(macgonuts_make_ethernet_frm(&ethfrm, NULL) == NULL);
    CUTE_ASSERT(macgonuts_read_ethernet_frm(&ethfrm, &frame_from_wire[0], frame_from_wire_size) == EXIT_SUCCESS);
    frm = macgonuts_make_ethernet_frm(&ethfrm, &frm_size);
    CUTE_ASSERT(frm != NULL);
    CUTE_ASSERT(frm_size == frame_from_wire_size);
    CUTE_ASSERT(memcmp(frm, frame_from_wire, frm_size) == 0);
    free(frm);
    macgonuts_release_ethfrm(&ethfrm);
CUTE_TEST_CASE_END
