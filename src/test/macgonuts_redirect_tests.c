/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_redirect_tests.h"
#include "macgonuts_mocks.h"
#include <macgonuts_redirect.h>
#include <macgonuts_socket.h>

CUTE_TEST_CASE(macgonuts_should_redirect_tests)
    struct macgonuts_spoofing_guidance_ctx spfgd = { 0 };
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
    struct test_ctx {
        const unsigned char *ethfrm;
        size_t ethfrm_size;
        uint8_t lo_hw_addr[6];
        uint8_t spoof_proto_addr[16];
        size_t proto_addr_size;
        int expected;
    } test_vector[] = {
        { frame_from_wire6,
          sizeof(frame_from_wire6),
          { 0x33, 0x33, 0xFF, 0x00, 0x00, 0x03 },
          { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x03 }, 16, 0 },
        { frame_from_wire6,
          sizeof(frame_from_wire6),
          { 0x33, 0x33, 0xFF, 0x00, 0x00, 0x03 },
          { 0xBA, 0xBA, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x03 }, 16, 1 },
        { frame_from_wire6,
          sizeof(frame_from_wire6),
          { 0x31, 0x33, 0xFF, 0x00, 0x00, 0x03 },
          { 0xBA, 0xBA, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x03 }, 16, 0 },
        { frame_from_wire4,
          sizeof(frame_from_wire4),
          { 0x33, 0x33, 0xFF, 0x00, 0x00, 0x03 },
          { 0x01, 0xBA, 0xBA, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 4, 0 },
        { frame_from_wire4,
          sizeof(frame_from_wire4),
          { 0x33, 0x33, 0xFF, 0x00, 0x00, 0x03 },
          { 0xC0, 0xA8, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 4, 1 },
        { frame_from_wire4,
          sizeof(frame_from_wire4),
          { 0x33, 0x33, 0xFF, 0x00, 0x00, 0x02 },
          { 0xC0, 0xA8, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 4, 0 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        memcpy(&spfgd.layers.lo_hw_addr[0], test->lo_hw_addr, sizeof(test->lo_hw_addr));
        spfgd.layers.proto_addr_size = test->proto_addr_size;
        memcpy(&spfgd.layers.spoof_proto_addr[0], test->spoof_proto_addr, test->proto_addr_size);
        CUTE_ASSERT(macgonuts_should_redirect(test->ethfrm, test->ethfrm_size, &spfgd.layers) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_redirect_tests)
#if defined(__linux__)
# define LO_IFACE "eth0"
#else
# Some code wanted
#endif // defined(__linux__)

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
    struct macgonuts_spoof_layers_ctx layers = { 0 };
    unsigned char *send_buf = NULL;
    size_t send_buf_size = 0;
    macgonuts_socket_t rsk = macgonuts_create_socket(LO_IFACE, 1);
    CUTE_ASSERT(rsk != -1);
    memcpy(&layers.lo_hw_addr[0], (uint8_t *)"\x33\x33\xFF\x00\x00\x03", 6);
    layers.proto_addr_size = 16;
    memcpy(&layers.spoof_hw_addr[0], (uint8_t *)"\x01\x02\x03\x04\x05\x06", 6);
    CUTE_ASSERT(macgonuts_redirect(rsk, &layers, frame_from_wire6, sizeof(frame_from_wire6), NULL) == ENODATA);
    memcpy(&layers.spoof_proto_addr[0], (uint8_t *)"\xBA\xBA\xCA\x00\x00\x00\x00\x00"
                                                   "\x00\x00\x00\x01\xFF\x00\x00\x03", 16);
    CUTE_ASSERT(macgonuts_redirect(rsk, &layers, frame_from_wire6, sizeof(frame_from_wire6), NULL) == EXIT_SUCCESS);
    send_buf = mock_get_send_buf(&send_buf_size);
    CUTE_ASSERT(send_buf_size == sizeof(frame_from_wire6));
    CUTE_ASSERT(memcmp(&send_buf[0], "\x01\x02\x03\x04\x05\x06", 6) == 0);
    macgonuts_release_socket(rsk);
CUTE_TEST_CASE_END
