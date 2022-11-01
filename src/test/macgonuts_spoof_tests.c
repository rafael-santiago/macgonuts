/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_spoof_tests.h"
#include "macgonuts_mocks.h"
#include <macgonuts_spoof.h>
#include <macgonuts_socket.h>

#if defined(__linux__)
# define DEFAULT_TEST_IFACE "eth0"
#else
# error Some code wanted.
#endif

CUTE_TEST_CASE(macgonuts_spoof_tests)
    const unsigned char expected_frame[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x06, 0x00, 0x01, 0x08, 0x00,
        0x06, 0x04, 0x00, 0x02, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x7F, 0x00,
        0x00, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x7F, 0x00, 0x00, 0x02
    };
    const size_t expected_frame_size = sizeof(expected_frame) / sizeof(expected_frame[0]);
    struct macgonuts_spoof_layers_ctx spf_layers = { 0 };
    int rsk = macgonuts_create_socket(DEFAULT_TEST_IFACE, 0);
    unsigned char *sent_spoof = NULL;
    size_t sent_spoof_size = 0;
    CUTE_ASSERT(rsk != -1);
    CUTE_ASSERT(macgonuts_spoof(-1, &spf_layers) == EINVAL);
    CUTE_ASSERT(macgonuts_spoof(rsk, NULL) == EINVAL);
    // INFO(Rafael): Spoof4 (arp).
    spf_layers.proto_addr_version = 4;
    spf_layers.proto_addr_size = 4;
    memcpy(&spf_layers.lo_hw_addr[0], "\xAA\xBB\xCC\xDD\xEE\xFF", sizeof(spf_layers.lo_hw_addr));
    memcpy(&spf_layers.lo_proto_addr[0], "\x7F\x00\x00\x01", sizeof(spf_layers.lo_proto_addr));
    memcpy(&spf_layers.tg_proto_addr[0], "\x7F\x00\x00\x02", sizeof(spf_layers.tg_proto_addr));
    memcpy(&spf_layers.spoof_proto_addr[0], "\x7F\x00\x00\x03", sizeof(spf_layers.spoof_proto_addr));
    memcpy(&spf_layers.tg_hw_addr[0], "\x00\x01\x02\x03\x04\x05", sizeof(spf_layers.tg_hw_addr));
    memcpy(&spf_layers.spoof_hw_addr[0], "\xAA\x01\xBB\x04\xCC\x05", sizeof(spf_layers.tg_hw_addr));
    CUTE_ASSERT(macgonuts_spoof(rsk, &spf_layers) == EXIT_SUCCESS);
    sent_spoof = mock_get_send_buf(&sent_spoof_size);
    CUTE_ASSERT(sent_spoof != NULL);
    CUTE_ASSERT(sent_spoof_size == expected_frame_size);
    CUTE_ASSERT(memcmp(&sent_spoof[0], &expected_frame[0], expected_frame_size) == 0);
    macgonuts_release_spoof_layers_ctx(&spf_layers);
    macgonuts_release_socket(rsk);
CUTE_TEST_CASE_END
