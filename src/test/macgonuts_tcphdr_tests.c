/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_tcphdr_tests.h"
#include <macgonuts_tcphdr.h>
#include <macgonuts_ip4hdr.h>

CUTE_TEST_CASE(macgonuts_read_tcp_pkt_tests)
    unsigned char dgram_from_wire[] = { 0x9B, 0xA6, 0x00, 0x50,
                                        0xAD, 0xC9, 0xB7, 0xA4,
                                        0x01, 0x2B, 0x50, 0x18,
                                        0x72, 0x10, 0x1D, 0x73,
                                        0x00, 0x00, 0x47, 0x45,
                                        0x54, 0x20, 0x2F, 0x20,
                                        0x48, 0x54, 0x54, 0x50,
                                        0x2F, 0x31, 0x2E, 0x30,
                                        0x0D, 0x0A, 0x48, 0x6F,
                                        0x73, 0x74, 0x3A, 0x20,
                                        0x67, 0x6F, 0x6F, 0x67,
                                        0x6C, 0x65, 0x2E, 0x63,
                                        0x6F, 0x6D, 0x0D, 0x0A,
                                        0x41, 0x63, 0x63, 0x65,
                                        0x70, 0x74, 0x3A, 0x20,
                                        0x74, 0x65, 0x78, 0x74,
                                        0x2F, 0x68, 0x74, 0x6D,
                                        0x6C, 0x2C, 0x20, 0x74,
                                        0x65, 0x78, 0x74, 0x2F,
                                        0x70, 0x6C, 0x61, 0x69,
                                        0x6E, 0x2C, 0x20, 0x74,
                                        0x65, 0x78, 0x74, 0x2F,
                                        0x73, 0x67, 0x6D, 0x6C,
                                        0x2C, 0x20, 0x74, 0x65,
                                        0x78, 0x74, 0x2F, 0x63,
                                        0x73, 0x73, 0x2C, 0x20,
                                        0x61, 0x70, 0x70, 0x6C,
                                        0x69, 0x63, 0x61, 0x74,
                                        0x69, 0x6F, 0x6E, 0x2F,
                                        0x78, 0x68, 0x74, 0x6D,
                                        0x6C, 0x2B, 0x78, 0x6D,
                                        0x6C, 0x2C, 0x20, 0x2A,
                                        0x2F, 0x2A, 0x3B, 0x71,
                                        0x3D, 0x30, 0x2E, 0x30,
                                        0x31, 0x0D, 0x0A, 0x41,
                                        0x63, 0x63, 0x65, 0x70,
                                        0x74, 0x2D, 0x45, 0x6E,
                                        0x63, 0x6F, 0x64, 0x69,
                                        0x6E, 0x67, 0x3A, 0x20,
                                        0x67, 0x7A, 0x69, 0x70,
                                        0x2C, 0x20, 0x63, 0x6F,
                                        0x6D, 0x70, 0x72, 0x65,
                                        0x73, 0x73, 0x2C, 0x20,
                                        0x62, 0x7A, 0x69, 0x70,
                                        0x32, 0x0D, 0x0A, 0x41,
                                        0x63, 0x63, 0x65, 0x70,
                                        0x74, 0x2D, 0x4C, 0x61,
                                        0x6E, 0x67, 0x75, 0x61,
                                        0x67, 0x65, 0x3A, 0x20,
                                        0x65, 0x6E, 0x0D, 0x0A,
                                        0x55, 0x73, 0x65, 0x72,
                                        0x2D, 0x41, 0x67, 0x65,
                                        0x6E, 0x74, 0x3A, 0x20,
                                        0x4C, 0x79, 0x6E, 0x78,
                                        0x2F, 0x32, 0x2E, 0x38,
                                        0x2E, 0x38, 0x72, 0x65,
                                        0x6C, 0x2E, 0x32, 0x20,
                                        0x6C, 0x69, 0x62, 0x77,
                                        0x77, 0x77, 0x2D, 0x46,
                                        0x4D, 0x2F, 0x32, 0x2E,
                                        0x31, 0x34, 0x20, 0x53,
                                        0x53, 0x4C, 0x2D, 0x4D,
                                        0x4D, 0x2F, 0x31, 0x2E,
                                        0x34, 0x2e, 0x31, 0x20,
                                        0x4F, 0x70, 0x65, 0x6E,
                                        0x53, 0x53, 0x4C, 0x2F,
                                        0x31, 0x2E, 0x30, 0x2E,
                                        0x32, 0x68, 0x0D, 0x0A,
                                        0x0D, 0x0A };
    size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_tcphdr_ctx tcphdr = { 0 };
    CUTE_ASSERT(macgonuts_read_tcp_pkt(NULL, dgram_from_wire, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_tcp_pkt(&tcphdr, NULL, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_tcp_pkt(&tcphdr, dgram_from_wire, 0) == EINVAL);
    CUTE_ASSERT(macgonuts_read_tcp_pkt(&tcphdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(tcphdr.src_port == 0x9BA6);
    CUTE_ASSERT(tcphdr.dest_port == 0x0050);
    CUTE_ASSERT(tcphdr.seqno == 0xADC9B7A4);
    CUTE_ASSERT(tcphdr.ackno == 0x012B5018);
    CUTE_ASSERT(tcphdr.doff_reserv_flags == 0x7210);
    CUTE_ASSERT(tcphdr.window == 0x1D73);
    CUTE_ASSERT(tcphdr.chsum == 0x0000);
    CUTE_ASSERT(tcphdr.urgptr == 0x4745);
    CUTE_ASSERT(tcphdr.options_size == 8);
    CUTE_ASSERT(tcphdr.options != NULL);
    CUTE_ASSERT(memcmp(&tcphdr.options[0], &dgram_from_wire[20], tcphdr.options_size) == 0);
    CUTE_ASSERT(tcphdr.payload_size == dgram_from_wire_size - tcphdr.options_size - 20);
    CUTE_ASSERT(tcphdr.payload != NULL);
    CUTE_ASSERT(memcmp(&tcphdr.payload[0], &dgram_from_wire[20 + tcphdr.options_size], tcphdr.payload_size) == 0);
    macgonuts_release_tcphdr(&tcphdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_tcp_pkt_tests)
    unsigned char dgram_from_wire[] = { 0x9B, 0xA6, 0x00, 0x50,
                                        0xAD, 0xC9, 0xB7, 0xA4,
                                        0x01, 0x2B, 0x50, 0x18,
                                        0x72, 0x10, 0x1D, 0x73,
                                        0x00, 0x00, 0x47, 0x45,
                                        0x54, 0x20, 0x2F, 0x20,
                                        0x48, 0x54, 0x54, 0x50,
                                        0x2F, 0x31, 0x2E, 0x30,
                                        0x0D, 0x0A, 0x48, 0x6F,
                                        0x73, 0x74, 0x3A, 0x20,
                                        0x67, 0x6F, 0x6F, 0x67,
                                        0x6C, 0x65, 0x2E, 0x63,
                                        0x6F, 0x6D, 0x0D, 0x0A,
                                        0x41, 0x63, 0x63, 0x65,
                                        0x70, 0x74, 0x3A, 0x20,
                                        0x74, 0x65, 0x78, 0x74,
                                        0x2F, 0x68, 0x74, 0x6D,
                                        0x6C, 0x2C, 0x20, 0x74,
                                        0x65, 0x78, 0x74, 0x2F,
                                        0x70, 0x6C, 0x61, 0x69,
                                        0x6E, 0x2C, 0x20, 0x74,
                                        0x65, 0x78, 0x74, 0x2F,
                                        0x73, 0x67, 0x6D, 0x6C,
                                        0x2C, 0x20, 0x74, 0x65,
                                        0x78, 0x74, 0x2F, 0x63,
                                        0x73, 0x73, 0x2C, 0x20,
                                        0x61, 0x70, 0x70, 0x6C,
                                        0x69, 0x63, 0x61, 0x74,
                                        0x69, 0x6F, 0x6E, 0x2F,
                                        0x78, 0x68, 0x74, 0x6D,
                                        0x6C, 0x2B, 0x78, 0x6D,
                                        0x6C, 0x2C, 0x20, 0x2A,
                                        0x2F, 0x2A, 0x3B, 0x71,
                                        0x3D, 0x30, 0x2E, 0x30,
                                        0x31, 0x0D, 0x0A, 0x41,
                                        0x63, 0x63, 0x65, 0x70,
                                        0x74, 0x2D, 0x45, 0x6E,
                                        0x63, 0x6F, 0x64, 0x69,
                                        0x6E, 0x67, 0x3A, 0x20,
                                        0x67, 0x7A, 0x69, 0x70,
                                        0x2C, 0x20, 0x63, 0x6F,
                                        0x6D, 0x70, 0x72, 0x65,
                                        0x73, 0x73, 0x2C, 0x20,
                                        0x62, 0x7A, 0x69, 0x70,
                                        0x32, 0x0D, 0x0A, 0x41,
                                        0x63, 0x63, 0x65, 0x70,
                                        0x74, 0x2D, 0x4C, 0x61,
                                        0x6E, 0x67, 0x75, 0x61,
                                        0x67, 0x65, 0x3A, 0x20,
                                        0x65, 0x6E, 0x0D, 0x0A,
                                        0x55, 0x73, 0x65, 0x72,
                                        0x2D, 0x41, 0x67, 0x65,
                                        0x6E, 0x74, 0x3A, 0x20,
                                        0x4C, 0x79, 0x6E, 0x78,
                                        0x2F, 0x32, 0x2E, 0x38,
                                        0x2E, 0x38, 0x72, 0x65,
                                        0x6C, 0x2E, 0x32, 0x20,
                                        0x6C, 0x69, 0x62, 0x77,
                                        0x77, 0x77, 0x2D, 0x46,
                                        0x4D, 0x2F, 0x32, 0x2E,
                                        0x31, 0x34, 0x20, 0x53,
                                        0x53, 0x4C, 0x2D, 0x4D,
                                        0x4D, 0x2F, 0x31, 0x2E,
                                        0x34, 0x2e, 0x31, 0x20,
                                        0x4F, 0x70, 0x65, 0x6E,
                                        0x53, 0x53, 0x4C, 0x2F,
                                        0x31, 0x2E, 0x30, 0x2E,
                                        0x32, 0x68, 0x0D, 0x0A,
                                        0x0D, 0x0A };
    size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_tcphdr_ctx tcphdr = { 0 };
    struct macgonuts_ip4_pseudo_hdr_ctx pheader = { 0 };
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;
    CUTE_ASSERT(macgonuts_read_tcp_pkt(&tcphdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_make_tcp_pkt(NULL, &pkt_size, NULL, 0) == NULL);
    CUTE_ASSERT(macgonuts_make_tcp_pkt(&tcphdr, NULL, NULL, 0) == NULL);
    pkt = macgonuts_make_tcp_pkt(&tcphdr, &pkt_size, NULL, 0);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
    pheader.src_addr = 0xA000020F;
    pheader.dest_addr = 0x8EFB814E;
    pheader.zprotolen = 0x00060000 | (dgram_from_wire_size & 0xFFFF);
    pkt = macgonuts_make_tcp_pkt(&tcphdr, &pkt_size, &pheader, sizeof(pheader));
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
    macgonuts_release_tcphdr(&tcphdr);
CUTE_TEST_CASE_END
