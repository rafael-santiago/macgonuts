#include "macgonuts_udphdr_tests.h"
#include <macgonuts_udphdr.h>
#include <macgonuts_ip4hdr.h>

CUTE_TEST_CASE(macgonuts_read_udp_pkt_tests)
    unsigned char dgram_from_wire[] = { 0x9F, 0xC3, 0x00, 0x35,
                                        0x00, 0x24, 0xD1, 0xED,
                                        0x35, 0x8F, 0x01, 0x00,
                                        0x00, 0x01, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00,
                                        0x06, 0x67, 0x6F, 0x6F,
                                        0x67, 0x6C, 0x65, 0x03,
                                        0x63, 0x6F, 0x6D, 0x00,
                                        0x00, 0x1C, 0x00, 0x01 };
    size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_udphdr_ctx udphdr = { 0 };
    CUTE_ASSERT(macgonuts_read_udp_pkt(NULL, dgram_from_wire, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_udp_pkt(&udphdr, NULL, dgram_from_wire_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_udp_pkt(&udphdr, dgram_from_wire, 0) == EINVAL);
    CUTE_ASSERT(macgonuts_read_udp_pkt(&udphdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(udphdr.src_port == 0x9FC3);
    CUTE_ASSERT(udphdr.dest_port == 0x0035);
    CUTE_ASSERT(udphdr.len == 0x0024);
    CUTE_ASSERT(udphdr.chsum == 0xD1ED);
    CUTE_ASSERT(udphdr.payload_size == 28);
    CUTE_ASSERT(udphdr.payload != NULL);
    CUTE_ASSERT(memcmp(&udphdr.payload[0], &dgram_from_wire[8], udphdr.payload_size) == 0);
    macgonuts_release_udphdr(&udphdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_udp_pkt_tests)
    unsigned char dgram_from_wire[] = { 0x9F, 0xC3, 0x00, 0x35,
                                        0x00, 0x24, 0xD1, 0xED,
                                        0x35, 0x8F, 0x01, 0x00,
                                        0x00, 0x01, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00,
                                        0x06, 0x67, 0x6F, 0x6F,
                                        0x67, 0x6C, 0x65, 0x03,
                                        0x63, 0x6F, 0x6D, 0x00,
                                        0x00, 0x1C, 0x00, 0x01 };
    size_t dgram_from_wire_size = sizeof(dgram_from_wire) / sizeof(dgram_from_wire[0]);
    struct macgonuts_udphdr_ctx udphdr = { 0 };
    struct macgonuts_ip4_pseudo_hdr_ctx pheader = { 0 };
    unsigned char *pkt = NULL;
    size_t pkt_size = 0;
    CUTE_ASSERT(macgonuts_read_udp_pkt(&udphdr, dgram_from_wire, dgram_from_wire_size) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_make_udp_pkt(NULL, &pkt_size, NULL, 0) == NULL);
    CUTE_ASSERT(macgonuts_make_udp_pkt(&udphdr, NULL, NULL, 0) == NULL);
    pkt = macgonuts_make_udp_pkt(&udphdr, &pkt_size, NULL, 0);
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
/*
    pheader.src_addr = 0x0A00020F;
    pheader.dest_addr = 0xC0A80501;
    pheader.zprotolen = 0x00110000 | (dgram_from_wire_size & 0xFFFF);
    pkt = macgonuts_make_udp_pkt(&udphdr, &pkt_size, &pheader, sizeof(pheader));
    CUTE_ASSERT(pkt != NULL);
    CUTE_ASSERT(pkt_size == dgram_from_wire_size);
    CUTE_ASSERT(memcmp(&pkt[0], &dgram_from_wire[0], pkt_size) == 0);
    free(pkt);
*/
    macgonuts_release_udphdr(&udphdr);
CUTE_TEST_CASE_END
