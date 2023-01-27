/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_DNSHDR_H
#define MACGONUTS_DNSHDR_H 1

#include <macgonuts_types.h>

typedef enum macgonuts_dns_type {
    kMacgonutsDNSTypeA = 1,
    kMacgonutsDNSTypeNS,
    kMacgonutsDNSTypeMD,
    kMacgonutsDNSTypeMF,
    kMacgonutsDNSTypeCNAME,
    kMacgonutsDNSTypeSOA,
    kMacgonutsDNSTypeMB,
    kMacgonutsDNSTypeMG,
    kMacgonutsDNSTypeMR,
    kMacgonutsDNSTypeNULL,
    kMacgonutsDNSTypeWKS,
    kMacgonutsDNSTypePTR,
    kMacgonutsDNSTypeHINFO,
    kMacgonutsDNSTypeMINFO,
    kMacgonutsDNSTypeMX,
    kMacgonutsDNSTypeTXT,
    kMacgonutsDNSQTypeAXFR = 252,
    kMacgonutsDNSQTypeMAILB,
    kMacgonutsDNSQTypeMAILA
}macgonuts_dns_type_t;

typedef enum macgonuts_dns_class {
    kMacgonutsDNSClassIN = 1,
    kMacgonutsDNSClassCS,
    kMacgonutsDNSClassCH,
    kMacgonutsDNSClassHS,
    kMacgonutsDNSQClassAny = 255
}macgonuts_dns_class_t;

struct macgonuts_dnshdr_ctx {
    uint16_t id;

    uint8_t qr;
    uint8_t opcode;
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t z;
    uint8_t rcode;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    uint8_t *rr;
    size_t rr_size;
};

struct macgonuts_dns_rr_hdr_ctx {
    size_t name_size;
    uint8_t *name;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
    struct macgonuts_dns_rr_hdr_ctx *next;
};

unsigned char *macgonuts_make_dns_pkt(const struct macgonuts_dnshdr_ctx *dnshdr, size_t *pkt_size);

int macgonuts_read_dns_pkt(struct macgonuts_dnshdr_ctx *dnshdr, const unsigned char *dnsbuf, const size_t dnsbuf_size);

int macgonuts_read_dns_resource_record(struct macgonuts_dns_rr_hdr_ctx *dnsrr,
                                       const struct macgonuts_dnshdr_ctx *dnshdr);

uint8_t *macgonuts_make_dns_an_pkt(const char *domain_name, const uint8_t *proto_addr, const size_t proto_addr_size);

void macgonuts_release_dnshdr(struct macgonuts_dnshdr_ctx *dnshdr);

void macgonuts_release_dns_rr_hdr(struct macgonuts_dns_rr_hdr_ctx *dnsrr);


#endif // MACGONUTS_DNSHDR_H
