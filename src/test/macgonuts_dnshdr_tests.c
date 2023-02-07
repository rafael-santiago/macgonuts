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
    CUTE_ASSERT(dnshdr.qd != NULL);
    CUTE_ASSERT(dnshdr.qd->rtype == 1);
    CUTE_ASSERT(dnshdr.qd->rclass == 1);
    CUTE_ASSERT(dnshdr.qd->name_size == 16);
    CUTE_ASSERT(dnshdr.qd->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr.qd->name, "aus5.mozilla.org", 16) == 0);
    CUTE_ASSERT(dnshdr.qd->next == NULL);
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
    CUTE_ASSERT(dnshdr.qd != NULL);
    CUTE_ASSERT(dnshdr.qd->rtype == 1);
    CUTE_ASSERT(dnshdr.qd->rclass == 1);
    CUTE_ASSERT(dnshdr.qd->name_size == 16);
    CUTE_ASSERT(dnshdr.qd->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr.qd->name, "aus5.mozilla.org", 16) == 0);
    CUTE_ASSERT(dnshdr.qd->next == NULL);
    CUTE_ASSERT(dnshdr.an != NULL);
    CUTE_ASSERT(dnshdr.an->name_size == 16);
    CUTE_ASSERT(dnshdr.an->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr.an->name, "aus5.mozilla.org", 16) == 0);
    CUTE_ASSERT(dnshdr.an->rtype == 5);
    CUTE_ASSERT(dnshdr.an->rclass == 1);
    CUTE_ASSERT(dnshdr.an->ttl == 7);
    CUTE_ASSERT(dnshdr.an->rdlength == 40);
    CUTE_ASSERT(dnshdr.an->rdata != NULL);
    CUTE_ASSERT(memcmp(dnshdr.an->rdata, &dns_reply[46], 40) == 0);
    CUTE_ASSERT(dnshdr.an->next != NULL);
    CUTE_ASSERT(dnshdr.an->next->name_size == 38);
    CUTE_ASSERT(dnshdr.an->next->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr.an->next->name, "balrog-aus5.r53-2.services.mozilla.com", 38) == 0);
    CUTE_ASSERT(dnshdr.an->next->rtype == 5);
    CUTE_ASSERT(dnshdr.an->next->rclass == 1);
    CUTE_ASSERT(dnshdr.an->next->ttl == 454);
    CUTE_ASSERT(dnshdr.an->next->rdlength == 38);
    CUTE_ASSERT(dnshdr.an->next->rdata != NULL);
    CUTE_ASSERT(memcmp(dnshdr.an->next->rdata, &dns_reply[98], 38) == 0);
    CUTE_ASSERT(dnshdr.an->next->next != NULL);
    CUTE_ASSERT(dnshdr.an->next->next->name_size == 36);
    CUTE_ASSERT(dnshdr.an->next->next->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr.an->next->next->name, "prod.balrog.prod.cloudops.mozgcp.net", 36) == 0);
    CUTE_ASSERT(dnshdr.an->next->next->rtype == 1);
    CUTE_ASSERT(dnshdr.an->next->next->rclass == 1);
    CUTE_ASSERT(dnshdr.an->next->next->ttl == 52);
    CUTE_ASSERT(dnshdr.an->next->next->rdlength == 4);
    CUTE_ASSERT(dnshdr.an->next->next->rdata != NULL);
    CUTE_ASSERT(memcmp(dnshdr.an->next->next->rdata, &dns_reply[148], 4) == 0);
    CUTE_ASSERT(dnshdr.an->next->next->next == NULL);
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
    struct macgonuts_dnshdr_ctx dnshdr_from_crafted_one = { 0 };
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
    // INFO(Rafael): Macgonuts has not been applying any kind of compression. Thus, the assembled packet
    //               size **MUST BE** different from the original one that applies some level of compression.
    CUTE_ASSERT(dnspkt_size != dns_reply_size);
    CUTE_ASSERT(memcmp(dnspkt, &dns_reply[0], dnspkt_size) != 0);
    // INFO(Rafael): Make a comparison between the data context read from the original packet and data context
    //               read from the crafted one is a straightforward way of checking on the right behavior of
    //               macgonuts_make_dns_pkt function. Since without using the same compression of the sample
    //               packet got from wire, the most trustworthy way of ensuring that even without compression
    //               we are getting the same packet data (from the compressed one) by using the crafted one.
    CUTE_ASSERT(macgonuts_read_dns_pkt(&dnshdr_from_crafted_one, dnspkt, dnspkt_size) == EXIT_SUCCESS);
    free(dnspkt);
    CUTE_ASSERT(dnshdr_from_crafted_one.id == dnshdr.id);
    CUTE_ASSERT(dnshdr_from_crafted_one.qr == dnshdr.qr);
    CUTE_ASSERT(dnshdr_from_crafted_one.opcode == dnshdr.opcode);
    CUTE_ASSERT(dnshdr_from_crafted_one.aa == dnshdr.aa);
    CUTE_ASSERT(dnshdr_from_crafted_one.tc == dnshdr.tc);
    CUTE_ASSERT(dnshdr_from_crafted_one.rd == dnshdr.rd);
    CUTE_ASSERT(dnshdr_from_crafted_one.ra == dnshdr.ra);
    CUTE_ASSERT(dnshdr_from_crafted_one.z == dnshdr.z);
    CUTE_ASSERT(dnshdr_from_crafted_one.rcode == dnshdr.rcode);
    CUTE_ASSERT(dnshdr_from_crafted_one.qdcount == dnshdr.qdcount);
    CUTE_ASSERT(dnshdr_from_crafted_one.ancount == dnshdr.ancount);
    CUTE_ASSERT(dnshdr_from_crafted_one.nscount == dnshdr.nscount);
    CUTE_ASSERT(dnshdr_from_crafted_one.arcount == dnshdr.arcount);
    CUTE_ASSERT(dnshdr_from_crafted_one.qd != NULL);
    CUTE_ASSERT(dnshdr_from_crafted_one.qd->name_size == dnshdr.qd->name_size);
    CUTE_ASSERT(dnshdr_from_crafted_one.qd->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.qd->name, dnshdr.qd->name, dnshdr.qd->name_size) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.qd->rtype == dnshdr.qd->rtype);
    CUTE_ASSERT(dnshdr_from_crafted_one.qd->rclass == dnshdr.qd->rclass);
    CUTE_ASSERT(dnshdr_from_crafted_one.qd->next == NULL);
    CUTE_ASSERT(dnshdr_from_crafted_one.an != NULL);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->name_size == dnshdr.an->name_size);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.an->name, dnshdr.an->name, dnshdr.an->name_size) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->rtype == dnshdr.an->rtype);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->rclass == dnshdr.an->rclass);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->ttl == dnshdr.an->ttl);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->rdlength == dnshdr.an->rdlength);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->rdata != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.an->rdata, dnshdr.an->rdata, dnshdr.an->rdlength) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next != NULL);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->name_size == dnshdr.an->next->name_size);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.an->next->name, dnshdr.an->next->name, dnshdr.an->next->name_size) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->rtype == dnshdr.an->next->rtype);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->rclass == dnshdr.an->next->rclass);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->ttl == dnshdr.an->next->ttl);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->rdlength == dnshdr.an->next->rdlength);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->rdata != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.an->next->rdata, dnshdr.an->next->rdata, dnshdr.an->next->rdlength) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next != NULL);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->name_size == dnshdr.an->next->next->name_size);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->name != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.an->next->next->name,
                       dnshdr.an->next->next->name, dnshdr.an->next->next->name_size) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->rtype == dnshdr.an->next->next->rtype);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->rclass == dnshdr.an->next->next->rclass);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->ttl == dnshdr.an->next->next->ttl);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->rdlength == dnshdr.an->next->next->rdlength);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->rdata != NULL);
    CUTE_ASSERT(memcmp(dnshdr_from_crafted_one.an->next->next->rdata,
                       dnshdr.an->next->next->rdata, dnshdr.an->next->next->rdlength) == 0);
    CUTE_ASSERT(dnshdr_from_crafted_one.an->next->next->next == NULL);
    macgonuts_release_dnshdr(&dnshdr_from_crafted_one);
    macgonuts_release_dnshdr(&dnshdr);
CUTE_TEST_CASE_END
