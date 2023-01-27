/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_dnshdr_tests.h"
#include <macgonuts_dnshdr.h>

CUTE_TEST_CASE(macgonuts_read_dns_pkt_tests)
    const unsigned char dns_request[] = { 0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x75, 0x73,
                                          0x35, 0x07, 0x6D, 0x6F, 0x7A, 0x69, 0x6C, 0x6C,
                                          0x61, 0x03, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x01,
                                          0x00, 0x01 };
    const size_t dns_request_size = sizeof(dns_request) / sizeof(dns_request[0]);
    const unsigned char dns_reply[] = { 0xAA, 0x85, 0x81, 0x80, 0x00, 0x01, 0x00,
                                        0x03, 0x00, 0x00, 0x00, 0x00, 0x04, 0x61,
                                        0x75, 0x73, 0x35, 0x07, 0x6D, 0x6F, 0x7A,
                                        0x69, 0x6C, 0x6C, 0x61, 0x03, 0x6F, 0x72,
                                        0x67, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
                                        0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
                                        0x00, 0x07, 0x00, 0x28, 0x0B, 0x62, 0x61,
                                        0x6C, 0x72, 0x6F, 0x67, 0x2D, 0x61, 0x75,
                                        0x73, 0x35, 0x05, 0x72, 0x35, 0x33, 0x2D,
                                        0x32, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69,
                                        0x63, 0x65, 0x73, 0x07, 0x6D, 0x6F, 0x7A,
                                        0x69, 0x6C, 0x6C, 0x61, 0x03, 0x63, 0x6F,
                                        0x6D, 0x00, 0xC0, 0x2E, 0x00, 0x05, 0x00,
                                        0x01, 0x00, 0x00, 0x01, 0xC6, 0x00, 0x26,
                                        0x04, 0x70, 0x72, 0x6F, 0x64, 0x06, 0x62,
                                        0x61, 0x6C, 0x72, 0x6F, 0x67, 0x04, 0x70,
                                        0x72, 0x6F, 0x64, 0x08, 0x63, 0x6C, 0x6F,
                                        0x75, 0x64, 0x6F, 0x70, 0x73, 0x06, 0x6D,
                                        0x6F, 0x7A, 0x67, 0x63, 0x70, 0x03, 0x6E,
                                        0x65, 0x74, 0x00, 0xC0, 0x62, 0x00, 0x01,
                                        0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                                        0x04, 0x23, 0xF4, 0xB5, 0xC9 };
    const size_t dns_reply_size = sizeof(dns_reply) / sizeof(dns_reply[0]);
    struct macgonuts_dnshdr_ctx dnshdr = { 0 };
    CUTE_ASSERT(macgonuts_read_dns_pkt(NULL, dns_request, dns_request_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr, NULL, dns_request_size) == EINVAL);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr, dns_request, 0) == EPROTO);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr, dns_request, dns_request_size) == EXIT_SUCCESS);
    CUTE_ASSERT(dnshdr.id == 0xAA85);
    CUTE_ASSERT(dnshdr.qr == 0);
    CUTE_ASSERT(dnshdr.opcode == 0);
    CUTE_ASSERT(dnshdr.aa == 0);
    CUTE_ASSERT(dnshdr.tc == 0);
    CUTE_ASSERT(dnshdr.rd == 1);
    CUTE_ASSERT(dnshdr.ra == 0);
    CUTE_ASSERT(dnshdr.z == 0);
    CUTE_ASSERT(dnshdr.rcode == 0);
    CUTE_ASSERT(dnshdr.qdcount == 1);
    CUTE_ASSERT(dnshdr.ancount == 0);
    CUTE_ASSERT(dnshdr.nscount == 0);
    CUTE_ASSERT(dnshdr.arcount == 0);
    CUTE_ASSERT(dnshdr.rr_size == 22);
    CUTE_ASSERT(dnshdr.rr != NULL);
    // INFO(Rafael): If some has leaked the memory leak check system will warn us.
    macgonuts_release_dnshdr(&dnshdr);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr, dns_reply, dns_reply_size) == EXIT_SUCCESS);
    CUTE_ASSERT(dnshdr.id == 0xAA85);
    CUTE_ASSERT(dnshdr.qr == 1);
    CUTE_ASSERT(dnshdr.opcode == 0);
    CUTE_ASSERT(dnshdr.aa == 0);
    CUTE_ASSERT(dnshdr.tc == 0);
    CUTE_ASSERT(dnshdr.rd == 1);
    CUTE_ASSERT(dnshdr.ra == 1);
    CUTE_ASSERT(dnshdr.z == 0);
    CUTE_ASSERT(dnshdr.rcode == 0);
    CUTE_ASSERT(dnshdr.qdcount == 1);
    CUTE_ASSERT(dnshdr.ancount == 3);
    CUTE_ASSERT(dnshdr.nscount == 0);
    CUTE_ASSERT(dnshdr.arcount == 0);
    CUTE_ASSERT(dnshdr.rr_size == 140);
    CUTE_ASSERT(dnshdr.rr != NULL);
    macgonuts_release_dnshdr(&dnshdr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_make_dns_pkt_tests)
    const unsigned char dns_request[] = { 0xAA, 0x85, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x75, 0x73,
                                          0x35, 0x07, 0x6D, 0x6F, 0x7A, 0x69, 0x6C, 0x6C,
                                          0x61, 0x03, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x01,
                                          0x00, 0x01 };
    const size_t dns_request_size = sizeof(dns_request) / sizeof(dns_request[0]);
    const unsigned char dns_reply[] = { 0xAA, 0x85, 0x81, 0x80, 0x00, 0x01, 0x00,
                                        0x03, 0x00, 0x00, 0x00, 0x00, 0x04, 0x61,
                                        0x75, 0x73, 0x35, 0x07, 0x6D, 0x6F, 0x7A,
                                        0x69, 0x6C, 0x6C, 0x61, 0x03, 0x6F, 0x72,
                                        0x67, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
                                        0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
                                        0x00, 0x07, 0x00, 0x28, 0x0B, 0x62, 0x61,
                                        0x6C, 0x72, 0x6F, 0x67, 0x2D, 0x61, 0x75,
                                        0x73, 0x35, 0x05, 0x72, 0x35, 0x33, 0x2D,
                                        0x32, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69,
                                        0x63, 0x65, 0x73, 0x07, 0x6D, 0x6F, 0x7A,
                                        0x69, 0x6C, 0x6C, 0x61, 0x03, 0x63, 0x6F,
                                        0x6D, 0x00, 0xC0, 0x2E, 0x00, 0x05, 0x00,
                                        0x01, 0x00, 0x00, 0x01, 0xC6, 0x00, 0x26,
                                        0x04, 0x70, 0x72, 0x6F, 0x64, 0x06, 0x62,
                                        0x61, 0x6C, 0x72, 0x6F, 0x67, 0x04, 0x70,
                                        0x72, 0x6F, 0x64, 0x08, 0x63, 0x6C, 0x6F,
                                        0x75, 0x64, 0x6F, 0x70, 0x73, 0x06, 0x6D,
                                        0x6F, 0x7A, 0x67, 0x63, 0x70, 0x03, 0x6E,
                                        0x65, 0x74, 0x00, 0xC0, 0x62, 0x00, 0x01,
                                        0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                                        0x04, 0x23, 0xF4, 0xB5, 0xC9 };
    const size_t dns_reply_size = sizeof(dns_reply) / sizeof(dns_reply[0]);
    struct macgonuts_dnshdr_ctx dnshdr = { 0 };
    unsigned char *dnspkt = NULL;
    size_t dnspkt_size = 0;
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr, dns_request, dns_request_size) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_make_dns_pkt(NULL, &dnspkt_size) == NULL);
    CUTE_ASSERT(macgonuts_make_dns_pkt(&dnshdr, NULL) == NULL);
    dnspkt = macgonuts_make_dns_pkt(&dnshdr, &dnspkt_size);
    CUTE_ASSERT(dnspkt != NULL);
    CUTE_ASSERT(dnspkt_size == dns_request_size);
    CUTE_ASSERT(memcmp(dnspkt, &dns_request[0], dnspkt_size) == 0);
    free(dnspkt);
    macgonuts_release_dnshdr(&dnshdr);
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr, dns_reply, dns_reply_size) == EXIT_SUCCESS);
    dnspkt = macgonuts_make_dns_pkt(&dnshdr, &dnspkt_size);
    CUTE_ASSERT(dnspkt != NULL);
    CUTE_ASSERT(dnspkt_size == dns_reply_size);
    CUTE_ASSERT(memcmp(dnspkt, &dns_reply[0], dnspkt_size) == 0);
    free(dnspkt);
    macgonuts_release_dnshdr(&dnshdr);
CUTE_TEST_CASE_END
