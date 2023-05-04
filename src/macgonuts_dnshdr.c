/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_dnshdr.h>
#include <macgonuts_dnsconv.h>

#define DNS_HDR_BASE_SIZE(c) (sizeof((c)->id) + 2 + sizeof((c)->qdcount) +\
                              sizeof((c)->ancount) + sizeof((c)->nscount) + sizeof((c)->arcount))

#define DNS_HDR_QSEC_BASE_SIZE(c) ( sizeof((c)->rtype) + sizeof((c)->rclass) )

#define DNS_HDR_GSEC_BASE_SIZE(c) ( sizeof((c)->rtype) + sizeof((c)->rclass) + sizeof((c)->ttl) + sizeof((c)->rdlength) )

static int read_dns_gsec(const unsigned char *dnsbuf, const unsigned char *dnsbuf_end, const unsigned char *dnspkt_head,
                         struct macgonuts_dns_rr_hdr_ctx *rrhdr, const int is_question_sec,
                         unsigned char **next);

static int read_dns_qsec(const unsigned char *dnsbuf, const unsigned char *dnsbuf_end, const unsigned char *dnspkt_head,
                         struct macgonuts_dns_rr_hdr_ctx *rrhdr, unsigned char **next);

static int make_gsec(unsigned char *pkt, unsigned char *pkt_end, const struct macgonuts_dnshdr_ctx *dnshdr,
                     const int is_question_sec, unsigned char **next);

static int make_qsec(unsigned char *pkt, unsigned char *pkt_end, const struct macgonuts_dnshdr_ctx *dnshdr,
                     unsigned char **next);

static struct macgonuts_dns_rr_hdr_ctx *create_rr_hdr_ctx(const size_t records_nr);

static void destroy_rr_hdr_ctx(struct macgonuts_dns_rr_hdr_ctx *rrhdr);

static size_t get_rr_hdr_size(const struct macgonuts_dnshdr_ctx *dnshdr);

unsigned char *macgonuts_make_dns_pkt(const struct macgonuts_dnshdr_ctx *dnshdr, size_t *pkt_size) {
    unsigned char *pkt = NULL;
    unsigned char *next = NULL;
    if (dnshdr == NULL || pkt_size == NULL) {
        return NULL;
    }

    *pkt_size = DNS_HDR_BASE_SIZE(dnshdr) + get_rr_hdr_size(dnshdr);
    pkt = (unsigned char *)malloc(*pkt_size);
    if (pkt == NULL) {
        *pkt_size = 0;
        return NULL;
    }

    pkt[ 0] = (dnshdr->id >> 8) & 0xFF;
    pkt[ 1] = dnshdr->id & 0xFF;
    pkt[ 2] = ((uint8_t)(dnshdr->qr & 1) << 7)        |
              ((uint8_t)(dnshdr->opcode & 0x0F) << 6) |
              ((uint8_t)(dnshdr->aa & 1) << 2)        |
              ((uint8_t)(dnshdr->tc & 1) << 1)        |
              ((uint8_t)(dnshdr->rd & 1));
    pkt[ 3] = ((uint8_t)(dnshdr->ra & 1) <<  7)       |
              ((uint8_t)(dnshdr->z & 0x0F) << 6)      |
              ((uint8_t)(dnshdr->rcode & 0x0F));
    pkt[ 4] = (dnshdr->qdcount >> 8) & 0xFF;
    pkt[ 5] = dnshdr->qdcount & 0xFF;
    pkt[ 6] = (dnshdr->ancount >> 8) & 0xFF;
    pkt[ 7] = dnshdr->ancount & 0xFF;
    pkt[ 8] = (dnshdr->nscount >> 8) & 0xFF;
    pkt[ 9] = dnshdr->nscount & 0xFF;
    pkt[10] = (dnshdr->arcount >> 8) & 0xFF;
    pkt[11] = dnshdr->arcount & 0xFF;

    if (dnshdr->qdcount > 0 && make_qsec(&pkt[12], pkt + *pkt_size, dnshdr, &next) != EXIT_SUCCESS) {
        free(pkt);
        pkt = NULL;
    }

    if (dnshdr->ancount > 0 && make_gsec(next, pkt + *pkt_size, dnshdr, 0, &next) != EXIT_SUCCESS) {
        free(pkt);
        pkt = NULL;
    }

    return pkt;
}

int macgonuts_read_dns_pkt(struct macgonuts_dnshdr_ctx *dnshdr, const unsigned char *dnsbuf, const size_t dnsbuf_size) {
    unsigned char *next = NULL;

    if (dnshdr == NULL
        || dnsbuf == NULL) {
        return EINVAL;
    }

    if (dnsbuf_size < DNS_HDR_BASE_SIZE(dnshdr)) {
        return EPROTO;
    }

    dnshdr->id = (uint16_t)dnsbuf[0] << 8 | (uint16_t)dnsbuf[1];

    dnshdr->qr = (dnsbuf[2] >> 7) & 1;
    dnshdr->opcode = (dnsbuf[2] >> 3) & 0x0F;
    dnshdr->aa = (dnsbuf[2] >> 2) & 1;
    dnshdr->tc = (dnsbuf[2] >> 1) & 1;
    dnshdr->rd = dnsbuf[2] & 1;
    dnshdr->ra = (dnsbuf[3] >> 7) & 1;
    dnshdr->z = (dnsbuf[3] >> 4) & 7;
    dnshdr->rcode = dnsbuf[3] & 0x0F;

    dnshdr->qdcount = (uint16_t)dnsbuf[ 4] << 8 | (uint16_t)dnsbuf[ 5];
    dnshdr->ancount = (uint16_t)dnsbuf[ 6] << 8 | (uint16_t)dnsbuf[ 7];
    dnshdr->nscount = (uint16_t)dnsbuf[ 8] << 8 | (uint16_t)dnsbuf[ 9];
    dnshdr->arcount = (uint16_t)dnsbuf[10] << 8 | (uint16_t)dnsbuf[11];

    dnshdr->qd = (dnshdr->qdcount > 0) ? create_rr_hdr_ctx(dnshdr->qdcount) : NULL;
    dnshdr->an = (dnshdr->ancount > 0) ? create_rr_hdr_ctx(dnshdr->ancount) : NULL;

    if (dnshdr->qd != NULL
        && read_dns_qsec(&dnsbuf[12], dnsbuf + dnsbuf_size, dnsbuf, dnshdr->qd, &next) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (dnshdr->an != NULL
        && read_dns_gsec(next, dnsbuf + dnsbuf_size, dnsbuf, dnshdr->an, 0, &next) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void macgonuts_release_dnshdr(struct macgonuts_dnshdr_ctx *dnshdr) {
    if (dnshdr == NULL) {
        return;
    }

    if (dnshdr->qd != NULL) {
        destroy_rr_hdr_ctx(dnshdr->qd);
    }

    if (dnshdr->an != NULL) {
        destroy_rr_hdr_ctx(dnshdr->an);
    }
}

int macgonuts_add_dns_answer(struct macgonuts_dnshdr_ctx *dnshdr, const uint8_t *proto_addr,
                             const size_t proto_addr_size, const uint32_t ttl_insecs) {
    if (dnshdr == NULL
        || proto_addr == NULL
        || dnshdr->qdcount == 0 || dnshdr->ancount > 0) {  // INFO(Rafael): It must be an unanswered question.
        return EINVAL;
    }

    if (proto_addr_size != 4 && proto_addr_size != 16) {
        return EPROTO;
    }

    dnshdr->ancount = 1;

    dnshdr->an = create_rr_hdr_ctx(1);

    if (dnshdr->an == NULL) {
        return ENOMEM;
    }

    dnshdr->an->name_size = 2;
    dnshdr->an->name = (uint8_t *)malloc(2);
    if (dnshdr->an->name == NULL) {
        dnshdr->an->name_size = 0;
        return ENOMEM;
    }

    dnshdr->an->rdata = (uint8_t *)malloc(proto_addr_size);
    if (dnshdr->an->rdata == NULL) {
        return ENOMEM;
    }
    dnshdr->an->rdlength = proto_addr_size;

    // INFO(Rafael): We will use compression, here we are pointing to the first label requested in the question
    //               record, which has the offset 12 as its starting point by taking into consideration the
    //               DNS datagram (isolated from the whole OSI stack, I meant).
    dnshdr->an->name[0] = 0xC0;
    dnshdr->an->name[1] = 0x0C;
    dnshdr->an->rtype = (proto_addr_size == 4) ? kMacgonutsDNSTypeA : kMacgonutsDNSTypeAAAA;
    dnshdr->an->rclass = kMacgonutsDNSClassIN;
    dnshdr->an->ttl = ttl_insecs;
    memcpy(dnshdr->an->rdata, proto_addr, proto_addr_size);

    return EXIT_SUCCESS;
}

static size_t get_rr_hdr_size(const struct macgonuts_dnshdr_ctx *dnshdr) {
    struct macgonuts_dns_rr_hdr_ctx *rp = NULL;
    size_t hdr_size = 0;
    for (rp = dnshdr->qd; rp != NULL; rp = rp->next) {
        hdr_size += DNS_HDR_QSEC_BASE_SIZE(rp) + rp->name_size + 2;
    }

    for (rp = dnshdr->an; rp != NULL; rp = rp->next) {
        hdr_size += DNS_HDR_GSEC_BASE_SIZE(rp) + rp->name_size + ((rp->name[0] != 0xC0) ? 2 : 0) + rp->rdlength;
    }

    return hdr_size;
}

static int read_dns_qsec(const unsigned char *dnsbuf, const unsigned char *dnsbuf_end, const unsigned char *dnspkt_head,
                         struct macgonuts_dns_rr_hdr_ctx *rrhdr, unsigned char **next) {
    return read_dns_gsec(dnsbuf, dnsbuf_end, dnspkt_head, rrhdr, 1, next);
}

static int read_dns_gsec(const unsigned char *dnsbuf, const unsigned char *dnsbuf_end, const unsigned char *dnspkt_head,
                         struct macgonuts_dns_rr_hdr_ctx *rrhdr, const int is_question_sec,
                         unsigned char **next) {
    int err = EXIT_SUCCESS;
    const unsigned char *db = dnsbuf;
    struct macgonuts_dns_rr_hdr_ctx *rp = rrhdr;
    size_t next_size = 0;
    const unsigned char *db_head = NULL;

    *next = NULL;

    while (rp != NULL && db < dnsbuf_end && err == EXIT_SUCCESS) {
        db_head = (*db == 0xC0) ? dnspkt_head + db[1] : db;
        rp->name = macgonuts_get_dns_u8str(db_head, dnsbuf_end - db_head, &rp->name_size, 0, 1);
        if (rp->name == NULL) {
            err = ENOMEM;
            continue;
        }
        //printf("[%p] name: %s %.2X%.2X\n", rrhdr, rp->name, db[0], db[1]);

        if (*db != 0xC0) {
            db += rp->name_size + 1;
            if (*db != 0) {
                err = EINVAL;
                continue;
            }
            db += 1;
        } else {
            db += 2;
        }
        next_size = sizeof(rp->rtype);

        if ((db + next_size) > dnsbuf_end) {
            err = ENOBUFS;
            continue;
        }
        rp->rtype = (uint16_t) db[0] << 8 | (uint16_t) db[1];
        db += next_size;
        next_size = sizeof(rp->rclass);

        if ((db + next_size) > dnsbuf_end) {
            err = ENOBUFS;
            continue;
        }
        rp->rclass = (uint16_t) db[0] << 8 | (uint16_t) db[1];
        db += next_size;

        if (!is_question_sec) {
            next_size = sizeof(rp->ttl);
            if ((db + next_size) > dnsbuf_end) {
                err = ENOBUFS;
                continue;
            }
            rp->ttl = (uint32_t) db[0] << 24 | (uint32_t) db[1] << 16 |
                      (uint32_t) db[2] <<  8 | (uint32_t) db[3];
            db += next_size;
            next_size = sizeof(rp->rdlength);

            if ((db + next_size) > dnsbuf_end) {
                err = ENOBUFS;
                continue;
            }
            rp->rdlength = (uint16_t) db[0] << 8 | (uint16_t) db[1];
            db += next_size;
            next_size = rp->rdlength;

            if ((db + next_size) > dnsbuf_end) {
                err = ENOBUFS;
                continue;
            }

            rp->rdata = (uint8_t *)malloc(next_size);
            if (rp->rdata == NULL) {
                err = ENOMEM;
                continue;
            }
            memcpy(rp->rdata, db, next_size);
            db += next_size;
        }

        rp = rp->next;
        if (rp != NULL && db > dnsbuf_end) {
            err = ENOBUFS;
            continue;
        }
    }

    if (err == EXIT_SUCCESS && rp == NULL) {
        *next = (unsigned char *)db;
    } else {
        err = EPROTO;
    }

    return err;
}

static int make_gsec(unsigned char *pkt, unsigned char *pkt_end, const struct macgonuts_dnshdr_ctx *dnshdr,
                     const int is_question_sec, unsigned char **next) {
    const struct macgonuts_dns_rr_hdr_ctx *rp = (is_question_sec) ? dnshdr->qd : dnshdr->an;
    unsigned char *pkt_p = pkt;
    uint8_t *label = NULL;
    size_t label_size;
    for (; rp != NULL; rp = rp->next) {
        if (rp->name[0] != 0xC0) {
            label = macgonuts_make_label_from_domain_name(rp->name, rp->name_size, &label_size);
            if (label == NULL
                || (pkt_end - pkt_p) < label_size) {
                return ENOBUFS;
            }
            memcpy(pkt_p, label, label_size);
            free(label);
            pkt_p += label_size + 1;
        } else {
            memcpy(pkt_p, rp->name, 2);
            pkt_p += 2;
        }

        label_size = sizeof(rp->rtype);
        if ((pkt_p + label_size) > pkt_end) {
            return ENOBUFS;
        }

        pkt_p[0] = (rp->rtype >> 8) & 0xFF;
        pkt_p[1] = rp->rtype & 0xFF;
        pkt_p += label_size;

        label_size = sizeof(rp->rclass);
        if ((pkt_p + label_size) > pkt_end) {
            return ENOBUFS;
        }
        pkt_p[0] = (rp->rclass >> 8) & 0xFF;
        pkt_p[1] = rp->rclass & 0xFF;
        pkt_p += label_size;

        if (!is_question_sec) {
            label_size = sizeof(rp->ttl);
            if ((pkt_p + label_size) > pkt_end) {
                return ENOBUFS;
            }
            pkt_p[0] = (rp->ttl >> 24) & 0xFF;
            pkt_p[1] = (rp->ttl >> 16) & 0xFF;
            pkt_p[2] = (rp->ttl >>  8) & 0xFF;
            pkt_p[3] = rp->ttl & 0xFF;
            pkt_p += label_size;

            label_size = sizeof(rp->rdlength);
            if ((pkt_p + label_size) > pkt_end) {
                return ENOBUFS;
            }
            pkt_p[0] = (rp->rdlength >> 8) & 0xFF;
            pkt_p[1] = rp->rdlength & 0xFF;
            pkt_p += label_size;

            label_size = rp->rdlength;
            if ((pkt_p + label_size) > pkt_end) {
                return ENOBUFS;
            }
            memcpy(pkt_p, rp->rdata, label_size);
            pkt_p += label_size;
        }
    }

    (*next) = pkt_p;

    return EXIT_SUCCESS;
}

static int make_qsec(unsigned char *pkt, unsigned char *pkt_end, const struct macgonuts_dnshdr_ctx *dnshdr,
                     unsigned char **next) {
    return make_gsec(pkt, pkt_end, dnshdr, 1, next);
}


static struct macgonuts_dns_rr_hdr_ctx *create_rr_hdr_ctx(const size_t records_nr) {
    size_t r;
    struct macgonuts_dns_rr_hdr_ctx *rrhdr = NULL;
    struct macgonuts_dns_rr_hdr_ctx *rp = NULL;

    if (records_nr == 0) {
        return NULL;
    }

    // INFO(Rafael): This more "tricky" way of allocating the needed data contexts is for
    //               do not stress up the system by requesting more work from the memory manager and,
    //               also make macgonuts able to release this resource quickly, as a resuly, it will
    //               occupy less the os' memory manager, too.

    r = sizeof(struct macgonuts_dns_rr_hdr_ctx) * records_nr;
    rrhdr = (struct macgonuts_dns_rr_hdr_ctx *)malloc(r);
    if (rrhdr == NULL) {
        return NULL;
    }
    memset(rrhdr, 0, r);

    rp = rrhdr;
    for (r = 1; r < records_nr; r++) {
        rp->next = rp + 1;
        rp = rp->next;
    }

    return rrhdr;
}

static void destroy_rr_hdr_ctx(struct macgonuts_dns_rr_hdr_ctx *rrhdr) {
    struct macgonuts_dns_rr_hdr_ctx *rp = rrhdr;

    if (rp == NULL) {
        return;
    }

    for (; rp != NULL; rp = rp->next) {
        if (rp->name != NULL) {
            free(rp->name);
        }

        if (rp->rdata != NULL) {
            free(rp->rdata);
        }
    }

    free(rrhdr);
}

#undef DNS_HDR_BASE_SIZE

#undef DNS_HDR_QSEC_BASE_SIZE

#undef DNS_HDR_GSEC_BASE_SIZE
