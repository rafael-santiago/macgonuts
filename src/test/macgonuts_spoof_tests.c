/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_spoof_tests.h"
#include "macgonuts_mocks.h"
#include "macgonuts_test_utils.h"
#include <macgonuts_spoof.h>
#include <macgonuts_socket.h>


CUTE_TEST_CASE(macgonuts_spoof_tests)
    const unsigned char expected_frame4[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x06, 0x00, 0x01, 0x08, 0x00,
        0x06, 0x04, 0x00, 0x02, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x7F, 0x00,
        0x00, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x7F, 0x00, 0x00, 0x02
    };
    const size_t expected_frame4_size = sizeof(expected_frame4) / sizeof(expected_frame4[0]);
    const unsigned char expected_frame6[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x86, 0xDD, 0x60, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x3A, 0xFF, 0xCA, 0xFE,
        0xCA, 0xFE, 0xCA, 0xFE, 0xCA, 0xFE,
        0xCA, 0xFE, 0xCA, 0xFE, 0xCA, 0xFE,
        0xCA, 0xFE, 0xFF, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x88, 0x00, 0x40, 0x1A, 0x20, 0x00,
        0x00, 0x00, 0xCA, 0xFE, 0xCA, 0xFE,
        0xCA, 0xFE, 0xCA, 0xFE, 0xCA, 0xFE,
        0xCA, 0xFE, 0xCA, 0xFE, 0xCA, 0xFE,
        0x02, 0x01, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF
    };
    const size_t expected_frame6_size = sizeof(expected_frame6) / sizeof(expected_frame6[0]);
    struct macgonuts_spoof_layers_ctx spf_layers = { 0 };
    int rsk = macgonuts_create_socket(get_default_iface_name(), 0);
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
    memcpy(&spf_layers.spoof_hw_addr[0], "\xAA\x01\xBB\x04\xCC\x05", sizeof(spf_layers.spoof_hw_addr));
    CUTE_ASSERT(macgonuts_spoof(rsk, &spf_layers) == EXIT_SUCCESS);
    sent_spoof = mock_get_send_buf(&sent_spoof_size);
    CUTE_ASSERT(sent_spoof != NULL);
    CUTE_ASSERT(sent_spoof_size == expected_frame4_size);
    CUTE_ASSERT(memcmp(&sent_spoof[0], &expected_frame4[0], expected_frame4_size) == 0);
    macgonuts_release_spoof_layers_ctx(&spf_layers);
    // INFO(Rafael): Spoof6 (ndp).
    spf_layers.proto_addr_version = 6;
    spf_layers.proto_addr_size = 16;
    memcpy(&spf_layers.lo_hw_addr[0], "\xAA\xBB\xCC\xDD\xEE\xFF", sizeof(spf_layers.lo_hw_addr));
    memcpy(&spf_layers.lo_proto_addr[0], "\xF0\xDA\x53\xF0\xDA\x53\xF0\xDA\x53\xF0\xDA\x53\xF0\xDA\x53\x00",
           sizeof(spf_layers.lo_proto_addr));
    memcpy(&spf_layers.spoof_proto_addr[0], "\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE",
           sizeof(spf_layers.spoof_proto_addr));
    memcpy(&spf_layers.tg_hw_addr[0], "\x00\x01\x02\x03\x04\x05", sizeof(spf_layers.tg_hw_addr));
    memcpy(&spf_layers.tg_proto_addr[0], "\xFE\xD1\xD0\xFE\xD1\xD0\xFE\xD1\xD0\xFE\xD1\xD0\xFE\xD1\xD0\x00",
           sizeof(spf_layers.tg_proto_addr));
    memcpy(&spf_layers.spoof_hw_addr[0], "\xAA\x01\xBB\x04\xCC\x05", sizeof(spf_layers.spoof_hw_addr));
    CUTE_ASSERT(macgonuts_spoof(rsk, &spf_layers) == EXIT_SUCCESS);
    sent_spoof = mock_get_send_buf(&sent_spoof_size);
    CUTE_ASSERT(sent_spoof != NULL);
    CUTE_ASSERT(sent_spoof_size == expected_frame6_size);
    CUTE_ASSERT(memcmp(&sent_spoof[0], &expected_frame6[0], expected_frame6_size) == 0);
    macgonuts_release_spoof_layers_ctx(&spf_layers);
    macgonuts_release_socket(rsk);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_spoof_layers_info_tests)
    macgonuts_socket_t rsk = macgonuts_create_socket(get_default_iface_name(), 0);
    struct macgonuts_spoof_layers_ctx spf_layers = { 0 };
    char *target_addr = NULL;
    size_t target_addr_size = 4;
    char *addr2spoof = NULL;
    size_t addr2spoof_size = 4;
    uint8_t expected_hw_addr[6] = { 0x08, 0x00, 0x27, 0x97, 0x64, 0x91 };
    CUTE_ASSERT(rsk != -1);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(-1,
                                                &spf_layers,
                                                target_addr, target_addr_size,
                                                addr2spoof, addr2spoof_size, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                NULL,
                                                target_addr, target_addr_size,
                                                addr2spoof, addr2spoof_size, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                NULL, target_addr_size,
                                                addr2spoof, addr2spoof_size, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                target_addr, 0,
                                                addr2spoof, addr2spoof_size, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                target_addr, target_addr_size,
                                                NULL, addr2spoof_size, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                target_addr, target_addr_size,
                                                addr2spoof, 0, get_default_iface_name()) == EINVAL);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                target_addr, target_addr_size,
                                                addr2spoof, addr2spoof_size, NULL) == EINVAL);
    target_addr = "10.0.2.13";
    target_addr_size = strlen(target_addr);
    addr2spoof = "2001::1";
    addr2spoof_size = strlen(addr2spoof);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                target_addr, target_addr_size,
                                                addr2spoof, addr2spoof_size, get_default_iface_name()) == EPROTO);
    addr2spoof = "10.0.2.11";
    addr2spoof_size = strlen(addr2spoof);
    CUTE_ASSERT(macgonuts_get_spoof_layers_info(rsk,
                                                &spf_layers,
                                                target_addr, target_addr_size,
                                                addr2spoof, addr2spoof_size, "blau0") != EXIT_SUCCESS);
CUTE_TEST_CASE_END
