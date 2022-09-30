/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_arphdr_tests.h"
#include <macgonuts_arphdr.h>

CUTE_TEST_CASE(macgonuts_make_arp_pkt_tests)
    unsigned char data_from_wire[] = { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
                                       0x01, 0x08, 0x00, 0x27, 0xFE, 0xEC, 0x1E,
                                       0x0A, 0x00, 0x02, 0x0F, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x03 };
    const size_t data_from_wire_size = sizeof(data_from_wire) / sizeof(data_from_wire[0]);
    struct macgonuts_arphdr_ctx arphdr = { 0 };
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;

    CUTE_ASSERT(macgonuts_make_arp_pkt(NULL, &pkt_size) == NULL);
    CUTE_ASSERT(macgonuts_make_arp_pkt(&arphdr, &pkt_size) == NULL);

    CUTE_ASSERT(macgonuts_read_arp_pkt(&arphdr, data_from_wire, data_from_wire_size) == EXIT_SUCCESS);

    CUTE_ASSERT(macgonuts_make_arp_pkt(&arphdr, NULL) == NULL);

    pkt = macgonuts_make_arp_pkt(&arphdr, &pkt_size);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == data_from_wire_size);
    CUTE_ASSERT(memcmp(pkt, data_from_wire, pkt_size) == 0);
    free(pkt);
    macgonuts_release_arphdr(&arphdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_read_arp_pkt_tests)
    unsigned char data_from_wire[] = { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
                                       0x01, 0x08, 0x00, 0x27, 0xFE, 0xEC, 0x1E,
                                       0x0A, 0x00, 0x02, 0x0F, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x03 };
    const size_t data_from_wire_size = sizeof(data_from_wire) / sizeof(data_from_wire[0]);
    struct macgonuts_arphdr_ctx arphdr = { 0 };

    CUTE_ASSERT(macgonuts_read_arp_pkt(NULL, data_from_wire, data_from_wire_size) == EINVAL);

    CUTE_ASSERT(macgonuts_read_arp_pkt(&arphdr, NULL, data_from_wire_size) == EINVAL);

    CUTE_ASSERT(macgonuts_read_arp_pkt(&arphdr, data_from_wire, 0) == EPROTO);

    CUTE_ASSERT(macgonuts_read_arp_pkt(&arphdr, data_from_wire, data_from_wire_size) == EXIT_SUCCESS);

    CUTE_ASSERT(arphdr.htype == 0x0001);
    CUTE_ASSERT(arphdr.ptype == 0x0800);
    CUTE_ASSERT(arphdr.hlen == 0x06);
    CUTE_ASSERT(arphdr.plen == 0x04);
    CUTE_ASSERT(arphdr.oper == 0x0001);
    CUTE_ASSERT(memcmp(arphdr.sha, &data_from_wire[8], (size_t)data_from_wire[4]) == 0);
    CUTE_ASSERT(memcmp(arphdr.spa, &data_from_wire[14], (size_t)data_from_wire[5]) == 0);
    CUTE_ASSERT(memcmp(arphdr.tha, &data_from_wire[18], (size_t)data_from_wire[4]) == 0);
    CUTE_ASSERT(memcmp(arphdr.tpa, &data_from_wire[24], (size_t)data_from_wire[5]) == 0);

    // INFO(Rafael): If any arphdr resource was not freed accordingly the memory leak check system will yell at us.
    macgonuts_release_arphdr(&arphdr);
CUTE_TEST_CASE_END

