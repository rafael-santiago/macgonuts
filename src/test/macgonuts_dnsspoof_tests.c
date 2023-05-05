/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_dnsspoof_tests.h"
#include "macgonuts_test_utils.h"
#include "macgonuts_mocks.h"
#include <macgonuts_socket.h>
#include <macgonuts_dnsspoof.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_ip4hdr.h>
#include <macgonuts_ip6hdr.h>
#include <macgonuts_udphdr.h>
#include <macgonuts_dnshdr.h>
#include <string.h>
#include <stdio.h>

CUTE_TEST_CASE(macgonuts_dnsspoof_tests)
    const char *etc_hoax_path = "lo-hoax";
    FILE *fp = NULL;
    macgonuts_iplist_handle *iplist = NULL;
    macgonuts_etc_hoax_handle *etc_hoax = NULL;
    const char *target_list = "192.30.70.2,192.30.70.3,dead::beef";
    const uint32_t dns_answer_ttl = 3600;
    macgonuts_socket_t rsk = -1;
    struct macgonuts_spoof_layers_ctx spf_layers = { 0 };
    const unsigned char non_dns_req_dgram4[] = {
        // INFO(Rafael): Ethernet frame.
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0xC0, 0x1E, 0x46, 0x02,
        0x08, 0x08, 0x08, 0x08,
        // INFO(Rafael): UDP datagram (No DNS).
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
    };
    const size_t non_dns_req_dgram4_size = sizeof(non_dns_req_dgram4) / sizeof(non_dns_req_dgram4[0]);
    const unsigned char expected_non_dns_req_dgram_redir4[] = {
        // INFO(Rafael): Ethernet frame.
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0xC0, 0x1E, 0x46, 0x02,
        0x08, 0x08, 0x08, 0x08,
        // INFO(Rafael): UDP datagram (No DNS).
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
    };
    const size_t expected_non_dns_req_dgram_redir4_size = sizeof(expected_non_dns_req_dgram_redir4) /
                                                            sizeof(expected_non_dns_req_dgram_redir4[0]);

    const unsigned char dns_req_dgram_no_relevant_query4[] = {
        // INFO(Rafael): Ethernet frame.
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0xC0, 0x1E, 0x46, 0x02,
        0x08, 0x08, 0x08, 0x08,
        // INFO(Rafael): UDP datagram.
        0x04, 0x00, 0x00, 0x35,
        0x00, 0x22, 0x00, 0x00,
        // INFO(Rafael): DNS datagram (with irrelevant query).
        0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x75, 0x73,
        0x35, 0x07, 0x6D, 0x6F, 0x7A, 0x69, 0x6C, 0x6C,
        0x61, 0x03, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    const size_t dns_req_dgram_no_relevant_query4_size = sizeof(dns_req_dgram_no_relevant_query4) /
                                                            sizeof(dns_req_dgram_no_relevant_query4[0]);

    const unsigned char expected_dns_req_dgram_no_relevant_query_redir4[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0xC0, 0x1E, 0x46, 0x02,
        0x08, 0x08, 0x08, 0x08,
        // INFO(Rafael): UDP datagram.
        0x04, 0x00, 0x00, 0x35,
        0x00, 0x22, 0x00, 0x00,
        // INFO(Rafael): DNS datagram (with irrelevant query).
        0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x75, 0x73,
        0x35, 0x07, 0x6D, 0x6F, 0x7A, 0x69, 0x6C, 0x6C,
        0x61, 0x03, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    const size_t expected_dns_req_dgram_no_relevant_query_redir4_size =
            sizeof(expected_dns_req_dgram_no_relevant_query_redir4) /
                sizeof(expected_dns_req_dgram_no_relevant_query_redir4[0]);
    const unsigned char dns_req_dgram_relevant_query4[] = {
        // INFO(Rafael): Ethernet frame.
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x08, 0x00,
        // INFO(Rafael): IP4 datagram.
        0x45, 0x00, 0x00, 0x38,
        0xDB, 0x08, 0x40, 0x00,
        0x40, 0x11, 0x8D, 0xF4,
        0xC0, 0x1E, 0x46, 0x02,
        0x08, 0x08, 0x08, 0x08,
        // INFO(Rafael): UDP datagram.
        0x04, 0x00, 0x00, 0x35,
        0x00, 0x24, 0x00, 0x00,
        // INFO(Rafael): DNS datagram (with irrelevant query).
        0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x6C, 0x6F, 0x67,
        0x69, 0x6E, 0x08, 0x66, 0x61, 0x6B, 0x65, 0x62,
        0x6F, 0x6F, 0x6B, 0x03, 0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    const size_t dns_req_dgram_relevant_query4_size = sizeof(dns_req_dgram_relevant_query4) /
                                                        sizeof(dns_req_dgram_relevant_query4[0]);
    const unsigned char non_dns_req_dgram6[] = {
        // INFO(Rafael): Ethernet frame.
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x24,
        0x11, 0xFF, 0xDE, 0xAD, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x88, 0x88,
        // INFO(Rafael): UDP datagram (No DNS).
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
    };
    const size_t non_dns_req_dgram6_size = sizeof(non_dns_req_dgram6) / sizeof(non_dns_req_dgram6[0]);
    const unsigned char expected_non_dns_req_dgram_redir6[] = {
        // INFO(Rafael): Ethernet frame.
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x24,
        0x11, 0xFF, 0xDE, 0xAD, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x88, 0x88,
        // INFO(Rafael): UDP datagram (No DNS).
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
        0x01, 0x10, 0x01, 0x10,
    };
    const size_t expected_non_dns_req_dgram_redir6_size = sizeof(expected_non_dns_req_dgram_redir6) /
                                                        sizeof(expected_non_dns_req_dgram_redir6[0]);
    const unsigned char dns_req_dgram_no_relevant_query6[] = {
        // INFO(Rafael): Ethernet frame.
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x2A,
        0x11, 0xFF, 0xDE, 0xAD, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x88, 0x88,
        // INFO(Rafael): UDP datagram.
        0x04, 0x00, 0x00, 0x35,
        0x00, 0x22, 0x00, 0x00,
        // INFO(Rafael): DNS datagram (with irrelevant query).
        0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x75, 0x73,
        0x35, 0x07, 0x6D, 0x6F, 0x7A, 0x69, 0x6C, 0x6C,
        0x61, 0x03, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    const size_t dns_req_dgram_no_relevant_query6_size = sizeof(dns_req_dgram_no_relevant_query6) /
                                                            sizeof(dns_req_dgram_no_relevant_query6[0]);
    const unsigned char expected_dns_req_dgram_no_relevant_query6[] = {
        // INFO(Rafael): Ethernet frame.
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x2A,
        0x11, 0xFF, 0xDE, 0xAD, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x88, 0x88,
        // INFO(Rafael): UDP datagram.
        0x04, 0x00, 0x00, 0x35,
        0x00, 0x22, 0x00, 0x00,
        // INFO(Rafael): DNS datagram (with irrelevant query).
        0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x75, 0x73,
        0x35, 0x07, 0x6D, 0x6F, 0x7A, 0x69, 0x6C, 0x6C,
        0x61, 0x03, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    const size_t expected_dns_req_dgram_no_relevant_query6_size =
        sizeof(expected_dns_req_dgram_no_relevant_query6) /
            sizeof(expected_dns_req_dgram_no_relevant_query6[0]);
    const unsigned char dns_req_dgram_relevant_query6[] = {
        // INFO(Rafael): Ethernet frame.
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x86, 0xDD,
        // INFO(Rafael): IP6 datagram.
        0x60, 0x00, 0x00, 0x00, 0x00, 0x2C,
        0x11, 0xFF, 0xDE, 0xAD, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x88, 0x88,
        // INFO(Rafael): UDP datagram.
        0x04, 0x00, 0x00, 0x35,
        0x00, 0x24, 0x00, 0x00,
        // INFO(Rafael): DNS datagram (with irrelevant query).
        0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x6C, 0x6F, 0x67,
        0x69, 0x6E, 0x08, 0x66, 0x61, 0x6B, 0x65, 0x62,
        0x6F, 0x6F, 0x6B, 0x03, 0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    const size_t dns_req_dgram_relevant_query6_size = sizeof(dns_req_dgram_relevant_query6) /
                                                        sizeof(dns_req_dgram_relevant_query6[0]);

    unsigned char *sent_buf = NULL;
    size_t sent_buf_size = 0;
    struct macgonuts_ethfrm_ctx eth = { 0 };
    struct macgonuts_ip4hdr_ctx ip4 = { 0 };
    struct macgonuts_ip6hdr_ctx ip6 = { 0 };
    struct macgonuts_udphdr_ctx udp = { 0 };
    struct macgonuts_dnshdr_ctx dns = { 0 };

    fp = fopen(etc_hoax_path, "wb");
    CUTE_ASSERT(fp != NULL);
    fprintf(fp, "192.30.70.8 *.fakebook.com\n");
    fclose(fp);

    etc_hoax = macgonuts_open_etc_hoax(etc_hoax_path);
    CUTE_ASSERT(etc_hoax != NULL);

    iplist = macgonuts_iplist_parse(target_list, strlen(target_list));
    CUTE_ASSERT(iplist != NULL);

    rsk = macgonuts_create_socket(get_default_iface_name(), 1);
    CUTE_ASSERT(rsk > -1);

    // INFO(Rafael): Testing ipv4 flow.

    spf_layers.proto_addr_version = 4;
    spf_layers.proto_addr_size = 4;
    spf_layers.spoofing_gateway = 1;

    memcpy(&spf_layers.lo_proto_addr[0], "\xC0\x1E\x46\x07", 4);
    memcpy(&spf_layers.tg_proto_addr[0], "\xC0\x1E\x46\x02", 4);
    memcpy(&spf_layers.spoof_proto_addr[0], "\xC0\x1E\x46\x01", 4);
    memcpy(&spf_layers.lo_hw_addr[0], "\xAA\xBB\xCC\xDD\xEE\xFF", sizeof(spf_layers.lo_hw_addr));
    memcpy(&spf_layers.spoof_hw_addr[0], "\xDE\xAD\xBE\xEF\x00\x00", sizeof(spf_layers.spoof_hw_addr));
    memcpy(&spf_layers.tg_hw_addr[0], "\x00\x00\xDE\xAD\xBE\xEF", sizeof(spf_layers.tg_hw_addr));

    CUTE_ASSERT(macgonuts_dnsspoof(rsk, &spf_layers,
                                   iplist, etc_hoax,
                                   dns_answer_ttl, non_dns_req_dgram4, non_dns_req_dgram4_size) == EPROTOTYPE);

    CUTE_ASSERT(macgonuts_dnsspoof(rsk, &spf_layers,
                                   iplist, etc_hoax,
                                   dns_answer_ttl,
                                   dns_req_dgram_no_relevant_query4,
                                   dns_req_dgram_no_relevant_query4_size) == EADDRNOTAVAIL);

    CUTE_ASSERT(macgonuts_dnsspoof(rsk, &spf_layers,
                                   iplist, etc_hoax,
                                   dns_answer_ttl,
                                   dns_req_dgram_relevant_query4,
                                   dns_req_dgram_relevant_query4_size) == EXIT_SUCCESS);

    sent_buf = mock_get_send_buf(&sent_buf_size);
    CUTE_ASSERT(sent_buf != NULL);
    CUTE_ASSERT(sent_buf_size > 0);

    CUTE_ASSERT(macgonuts_read_ethernet_frm(&eth, sent_buf, sent_buf_size) == EXIT_SUCCESS);
    CUTE_ASSERT(eth.ether_type == MACGONUTS_ETHER_TYPE_IP4);
    CUTE_ASSERT(memcmp(&eth.src_hw_addr[0], &dns_req_dgram_relevant_query4[0], sizeof(eth.src_hw_addr)) == 0);
    CUTE_ASSERT(memcmp(&eth.dest_hw_addr[0], &dns_req_dgram_relevant_query4[6], sizeof(eth.dest_hw_addr)) == 0);
    CUTE_ASSERT(macgonuts_read_ip4_pkt(&ip4, eth.data, eth.data_size) == EXIT_SUCCESS);
    CUTE_ASSERT(ip4.dest_addr == 0xC01E4602);
    CUTE_ASSERT(ip4.src_addr == 0x08080808);
    CUTE_ASSERT(ip4.proto == 17);
    CUTE_ASSERT(macgonuts_read_udp_pkt(&udp, ip4.payload, ip4.payload_size) == EXIT_SUCCESS);
    CUTE_ASSERT(udp.src_port == 53);
    CUTE_ASSERT(udp.dest_port == 1024);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dns, udp.payload, udp.payload_size) == EXIT_SUCCESS);
    CUTE_ASSERT(dns.id == 0xAA85);
    CUTE_ASSERT(dns.ancount == 1);
    CUTE_ASSERT(dns.an != NULL);
    CUTE_ASSERT(dns.an->name_size == 18);
    CUTE_ASSERT(memcmp(dns.an->name, "login.fakebook.com", 18) == 0);
    CUTE_ASSERT(dns.an->rtype == kMacgonutsDNSTypeA);
    CUTE_ASSERT(dns.an->rclass == kMacgonutsDNSClassIN);
    CUTE_ASSERT(dns.an->ttl == dns_answer_ttl);
    CUTE_ASSERT(dns.an->rdlength == 4);
    CUTE_ASSERT(memcmp(dns.an->rdata, "\xC0\x1E\x46\x08", 4) == 0);
    CUTE_ASSERT(dns.an->next == NULL);

    macgonuts_release_dnshdr(&dns);
    macgonuts_release_udphdr(&udp);
    macgonuts_release_ip4hdr(&ip4);
    macgonuts_release_ethfrm(&eth);

    macgonuts_iplist_release(iplist);
    macgonuts_close_etc_hoax(etc_hoax);

    // INFO(Rafael): Testing ipv6 flow.

    fp = fopen(etc_hoax_path, "wb");
    CUTE_ASSERT(fp != NULL);
    fprintf(fp, "2001::BABA:CA00 *.fakebook.com\n");
    fclose(fp);

    etc_hoax = macgonuts_open_etc_hoax(etc_hoax_path);
    CUTE_ASSERT(etc_hoax != NULL);

    iplist = macgonuts_iplist_parse(target_list, strlen(target_list));
    CUTE_ASSERT(iplist != NULL);

    spf_layers.proto_addr_version = 6;
    spf_layers.proto_addr_size = 16;
    spf_layers.spoofing_gateway = 1;

    memcpy(&spf_layers.lo_proto_addr[0], "DEAD::BEE2", 4);
    memcpy(&spf_layers.tg_proto_addr[0], "DEAD::BEEF", 4);
    memcpy(&spf_layers.spoof_proto_addr[0], "DEAD::BEE0", 4);
    memcpy(&spf_layers.lo_hw_addr[0], "\xAA\xBB\xCC\xDD\xEE\xFF", sizeof(spf_layers.lo_hw_addr));
    memcpy(&spf_layers.spoof_hw_addr[0], "\xDE\xAD\xBE\xEF\x00\x00", sizeof(spf_layers.spoof_hw_addr));
    memcpy(&spf_layers.tg_hw_addr[0], "\x00\x00\xDE\xAD\xBE\xEF", sizeof(spf_layers.tg_hw_addr));

    CUTE_ASSERT(macgonuts_dnsspoof(rsk, &spf_layers,
                                   iplist, etc_hoax,
                                   dns_answer_ttl,
                                   non_dns_req_dgram6,
                                   non_dns_req_dgram6_size) == EPROTOTYPE);

    CUTE_ASSERT(macgonuts_dnsspoof(rsk, &spf_layers,
                                   iplist, etc_hoax,
                                   dns_answer_ttl,
                                   dns_req_dgram_no_relevant_query6,
                                   dns_req_dgram_no_relevant_query6_size) == EADDRNOTAVAIL);

    CUTE_ASSERT(macgonuts_dnsspoof(rsk, &spf_layers,
                                   iplist, etc_hoax,
                                   dns_answer_ttl,
                                   dns_req_dgram_relevant_query6,
                                   dns_req_dgram_relevant_query6_size) == EXIT_SUCCESS);

    sent_buf = mock_get_send_buf(&sent_buf_size);
    CUTE_ASSERT(sent_buf != NULL);
    CUTE_ASSERT(sent_buf_size > 0);

    CUTE_ASSERT(macgonuts_read_ethernet_frm(&eth, sent_buf, sent_buf_size) == EXIT_SUCCESS);
    CUTE_ASSERT(eth.ether_type == MACGONUTS_ETHER_TYPE_IP6);
    CUTE_ASSERT(memcmp(&eth.src_hw_addr[0], &dns_req_dgram_relevant_query6[0], sizeof(eth.src_hw_addr)) == 0);
    CUTE_ASSERT(memcmp(&eth.dest_hw_addr[0], &dns_req_dgram_relevant_query6[6], sizeof(eth.dest_hw_addr)) == 0);
    CUTE_ASSERT(macgonuts_read_ip6_pkt(&ip6, eth.data, eth.data_size) == EXIT_SUCCESS);
    CUTE_ASSERT(memcmp(&ip6.src_addr[0], &dns_req_dgram_relevant_query6[38], sizeof(ip6.src_addr)) == 0);
    CUTE_ASSERT(memcmp(&ip6.dest_addr[0], &dns_req_dgram_relevant_query6[22], sizeof(ip6.dest_addr)) == 0);
    CUTE_ASSERT(ip6.next_header == 17);
    CUTE_ASSERT(macgonuts_read_udp_pkt(&udp, ip6.payload, ip6.payload_length) == EXIT_SUCCESS);
    CUTE_ASSERT(udp.src_port == 53);
    CUTE_ASSERT(udp.dest_port == 1024);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dns, udp.payload, udp.payload_size) == EXIT_SUCCESS);
    CUTE_ASSERT(dns.id == 0xAA85);
    CUTE_ASSERT(dns.ancount == 1);
    CUTE_ASSERT(dns.an != NULL);
    CUTE_ASSERT(dns.an->name_size == 18);
    CUTE_ASSERT(memcmp(dns.an->name, "login.fakebook.com", 18) == 0);
    CUTE_ASSERT(dns.an->rtype == kMacgonutsDNSTypeAAAA);
    CUTE_ASSERT(dns.an->rclass == kMacgonutsDNSClassIN);
    CUTE_ASSERT(dns.an->ttl == dns_answer_ttl);
    CUTE_ASSERT(dns.an->rdlength == 16);
    CUTE_ASSERT(memcmp(dns.an->rdata, "\x20\x01\x00\x00\x00\x00\x00\x00"
                                      "\x00\x00\x00\x00\xBA\xBA\xCA\x00", 16) == 0);
    CUTE_ASSERT(dns.an->next == NULL);

    macgonuts_release_dnshdr(&dns);
    macgonuts_release_udphdr(&udp);
    macgonuts_release_ip6hdr(&ip6);
    macgonuts_release_ethfrm(&eth);

    macgonuts_iplist_release(iplist);
    macgonuts_close_etc_hoax(etc_hoax);
    macgonuts_release_socket(rsk);
    remove(etc_hoax_path);
CUTE_TEST_CASE_END
