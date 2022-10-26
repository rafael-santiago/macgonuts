/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_arphdr.h>
#include <macgonuts_ip6hdr.h>
#include <macgonuts_icmphdr.h>
#include <macgonuts_ndphdr.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ip6mcast.h>
#include <macgonuts_socket.h>
#include <macgonuts_status_info.h>

typedef int (*get_ethaddr_handler_func)(uint8_t *hw_addr, const size_t hw_addr_size,
                                        const char *layer3addr, const size_t layer3addr_size,
                                        const macgonuts_socket_t rsk, const char *iface);

static int get_ethaddr_ip4(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           const macgonuts_socket_t rsk, const char *iface);

static int get_ethaddr_ip6(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           const macgonuts_socket_t rsk, const char *iface);

static int get_ethaddr_unk(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           const macgonuts_socket_t rsk, const char *iface);

int macgonuts_get_ethaddr(uint8_t *hw_addr, const size_t hw_addr_size,
                          const char *layer3addr, const size_t layer3addr_size,
                          const macgonuts_socket_t rsk, const char *iface) {
    get_ethaddr_handler_func get_ethaddr = NULL;
    int l3addr_version = 0;

    if (hw_addr == NULL || hw_addr_size != 6 || layer3addr == NULL || layer3addr_size == 0) {
        return EINVAL;
    }

    l3addr_version = macgonuts_get_ip_version(layer3addr, layer3addr_size);

    get_ethaddr = (l3addr_version == 4) ? get_ethaddr_ip4 :
                  (l3addr_version == 6) ? get_ethaddr_ip6 : get_ethaddr_unk;

    assert(get_ethaddr != NULL);

    return get_ethaddr(hw_addr, hw_addr_size, layer3addr, layer3addr_size, rsk, iface);
}

static int get_ethaddr_ip4(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           const macgonuts_socket_t rsk, const char *iface) {
    int err = EFAULT;
    struct macgonuts_ethfrm_ctx ethfrm = { 0 };
    struct macgonuts_arphdr_ctx arp_req_hdr = { 0 }, arp_rep_hdr = { 0 };
    char src_hw_addr[20] = { 0 };
    char src_ip_addr[20] = { 0 };
    int ntry = 10, rtry = 0;
    int done = 0;
    ssize_t bytes_nr = 0;
    unsigned char *arp_req_pkt = NULL;
    size_t arp_req_pkt_size = 0;
    unsigned char arp_rep_pkt[1<<10] = { 0 };
    size_t arp_rep_pkt_size = 0;

    // INFO(Rafael): Crafting ethernet frame.
    err = macgonuts_get_raw_ether_addr(ethfrm.dest_hw_addr, sizeof(ethfrm.dest_hw_addr),
                                       "FF:FF:FF:FF:FF:FF", 17);

    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip4_epilogue;
    }

    err = macgonuts_get_mac_from_iface(src_hw_addr, sizeof(src_hw_addr), iface);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip4_epilogue;
    }

    err = macgonuts_get_addr_from_iface(src_ip_addr, sizeof(src_ip_addr), 4, iface);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip4_epilogue;
    }

    err = macgonuts_get_raw_ether_addr(ethfrm.src_hw_addr, sizeof(ethfrm.src_hw_addr),
                                       src_hw_addr, strlen(src_hw_addr));
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip4_epilogue;
    }

    ethfrm.ether_type = MACGONUTS_ETHER_TYPE_ARP;

    // INFO(Rafael): Now crafting out our ARP request header.
    arp_req_hdr.htype = MACGONUTS_ARP_HW_TYPE_ETHERNET;
    arp_req_hdr.ptype = MACGONUTS_ETHER_TYPE_IP4;
    arp_req_hdr.hlen = sizeof(ethfrm.dest_hw_addr);
    arp_req_hdr.plen = sizeof(uint32_t);
    arp_req_hdr.oper = kARPOperRequest;
    arp_req_hdr.sha = (uint8_t *)malloc(arp_req_hdr.hlen);

    if (arp_req_hdr.sha == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip4_epilogue;
    }

    arp_req_hdr.spa = (uint8_t *)malloc(arp_req_hdr.plen);
    if (arp_req_hdr.spa == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip4_epilogue;
    }

    arp_req_hdr.tha = (uint8_t *)malloc(arp_req_hdr.hlen);
    if (arp_req_hdr.tha == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip4_epilogue;
    }

    arp_req_hdr.tpa = (uint8_t *)malloc(arp_req_hdr.plen);
    if (arp_req_hdr.tpa == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip4_epilogue;
    }

    if (macgonuts_get_raw_ip_addr(arp_req_hdr.spa, arp_req_hdr.plen, src_ip_addr, strlen(src_ip_addr)) != EXIT_SUCCESS
        || macgonuts_get_raw_ip_addr(arp_req_hdr.tpa, arp_req_hdr.plen, layer3addr, layer3addr_size) != EXIT_SUCCESS) {
        err = EINVAL;
        goto get_ethaddr_ip4_epilogue;
    }

    assert(arp_req_hdr.hlen == sizeof(ethfrm.src_hw_addr));

    memcpy(arp_req_hdr.sha, ethfrm.src_hw_addr, arp_req_hdr.hlen);
    memset(arp_req_hdr.tha, 0, arp_req_hdr.hlen);

    // INFO(Rafael): Finally, crafting the whole ethernet frame and sending it.
    ethfrm.data = (uint8_t *)macgonuts_make_arp_pkt(&arp_req_hdr, &ethfrm.data_size);
    if (ethfrm.data == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip4_epilogue;
    }

    arp_req_pkt = macgonuts_make_ethernet_frm(&ethfrm, &arp_req_pkt_size);
    if (arp_req_pkt == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip4_epilogue;
    }

    err = EFAULT;

    do {
        bytes_nr = macgonuts_sendpkt(rsk, arp_req_pkt, arp_req_pkt_size);
        if (bytes_nr == -1) {
            err = errno;
            continue;
        }

        bytes_nr = macgonuts_recvpkt(rsk, arp_rep_pkt, sizeof(arp_rep_pkt));
        if (bytes_nr == -1) {
            continue;
        }

        macgonuts_release_arphdr(&arp_rep_hdr);
        macgonuts_release_ethfrm(&ethfrm);

        err = macgonuts_read_ethernet_frm(&ethfrm, arp_rep_pkt, bytes_nr);
        if (err != EXIT_SUCCESS
            || ethfrm.ether_type != MACGONUTS_ETHER_TYPE_ARP) {
            continue;
        }

        err = macgonuts_read_arp_pkt(&arp_rep_hdr, ethfrm.data, ethfrm.data_size);
        if (err != EXIT_SUCCESS
            || arp_rep_hdr.oper != kARPOperReply
            || memcmp(arp_rep_hdr.spa, arp_req_hdr.tpa, arp_rep_hdr.plen) != 0
            || memcmp(arp_rep_hdr.tpa, arp_req_hdr.spa, arp_rep_hdr.plen) != 0) {
            continue;
        }

        if (hw_addr_size < arp_rep_hdr.hlen) {
            err = ERANGE;
            goto get_ethaddr_ip4_epilogue;
        }

        memcpy(hw_addr, arp_rep_hdr.sha, arp_rep_hdr.hlen);
        err = EXIT_SUCCESS;
        done = 1;
    } while (!done && ntry-- > 0);

get_ethaddr_ip4_epilogue:

    macgonuts_release_arphdr(&arp_req_hdr);
    macgonuts_release_arphdr(&arp_rep_hdr);
    macgonuts_release_ethfrm(&ethfrm);

    if (arp_req_pkt != NULL) {
        free(arp_req_pkt);
        arp_req_pkt = NULL;
        arp_req_pkt_size = 0;
    }

    return err;
}

static int get_ethaddr_ip6(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           const macgonuts_socket_t rsk, const char *iface) {
    char src_hw_addr[20] = { 0 };
    char src_ip_addr[50] = { 0 };
    int err = EFAULT;
    struct macgonuts_ethfrm_ctx ethfrm_req = { 0 }, ethfrm_rep = { 0 };
    struct macgonuts_ip6hdr_ctx ip6hdr_req = { 0 }, ip6hdr_rep = { 0 };
    struct macgonuts_icmphdr_ctx icmphdr_req = { 0 }, icmphdr_rep = { 0 };
    struct macgonuts_ndp_nsna_hdr_ctx ndp_ns_hdr = { 0 }, ndp_na_hdr = { 0 };
    struct macgonuts_ip6_pseudo_hdr_ctx ip6phdr_req = { 0 };
    unsigned char *ns_pkt = NULL;
    size_t ns_pkt_size = 0, icmp_pkt_size = 0;
    int done = 0;
    int ntry = 10;
    unsigned char na_pkt[1<<10] = { 0 };
    ssize_t na_pkt_size = 0;
    uint8_t unicast_dest_addr[16] = { 0 };

    err = macgonuts_get_mac_from_iface(src_hw_addr, sizeof(src_hw_addr), iface);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    err = macgonuts_get_addr_from_iface(src_ip_addr, sizeof(src_ip_addr), 6, iface);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    err = macgonuts_get_raw_ip6_mcast_ether_addr(ethfrm_req.dest_hw_addr, sizeof(ethfrm_req.dest_hw_addr),
                                                 layer3addr, layer3addr_size);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    err = macgonuts_get_raw_ether_addr(ethfrm_req.src_hw_addr, sizeof(ethfrm_req.src_hw_addr),
                                       src_hw_addr, strlen(src_hw_addr));
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    ethfrm_req.ether_type = MACGONUTS_ETHER_TYPE_IP6;

    ip6hdr_req.version = 6;
    ip6hdr_req.priority = 0;
    ip6hdr_req.flow_label = 0;
    // INFO(Rafael): We will send the MAC of the requestor in ICMP options, more on later.
    ip6hdr_req.payload_length = 0;
    ip6hdr_req.next_header = 0x3A;
    ip6hdr_req.hop_limit = 0xFF;

    err = macgonuts_get_raw_ip_addr(&ip6hdr_req.src_addr[0], sizeof(ip6hdr_req.src_addr),
                                    src_ip_addr, strlen(src_ip_addr));
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    err = macgonuts_get_multicast_addr(&ip6hdr_req.dest_addr[0], sizeof(ip6hdr_req.dest_addr),
                                       layer3addr, layer3addr_size);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    err = macgonuts_get_raw_ip_addr(&unicast_dest_addr[0], sizeof(unicast_dest_addr),
                                    layer3addr, layer3addr_size);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    icmphdr_req.type = kNDPMsgTypeNeighborSolicitation;
    icmphdr_req.code = 0;
    icmphdr_req.chsum = 0;

    err = macgonuts_get_raw_ip_addr((uint8_t *)&ndp_ns_hdr.target_addr, 16, layer3addr, layer3addr_size);
    if (err != EXIT_SUCCESS) {
        goto get_ethaddr_ip6_epilogue;
    }

    ndp_ns_hdr.options_size = 8;
    ndp_ns_hdr.options = (uint8_t *)malloc(ndp_ns_hdr.options_size);
    if (ndp_ns_hdr.options == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip6_epilogue;
    }

    ndp_ns_hdr.options[0] = 0x01; // INFO(Rafael): 'Source Link-Layer Address'
    ndp_ns_hdr.options[1] = 0x01; // INFO(Rafael): Number of octets to store the option including type and length parts.
    memcpy(&ndp_ns_hdr.options[2], ethfrm_req.src_hw_addr, sizeof(ethfrm_req.src_hw_addr));

    icmphdr_req.payload = (uint8_t *)macgonuts_make_ndp_nsna_pkt(&ndp_ns_hdr, &icmphdr_req.payload_size);
    if (icmphdr_req.payload == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip6_epilogue;
    }

    memcpy(&ip6phdr_req.src_addr[0], &ip6hdr_req.src_addr[0], sizeof(ip6phdr_req.src_addr));
    memcpy(&ip6phdr_req.dest_addr[0], &ip6hdr_req.dest_addr[0], sizeof(ip6phdr_req.dest_addr));
    // INFO(Rafael): Base size of icmp (type, code, checksum and what it carries, in this case our ICMPv6[NDP/NS])
    icmp_pkt_size = 4 + icmphdr_req.payload_size;
    ip6phdr_req.upper_layer_pkt_len[0] = (icmp_pkt_size >> 24) & 0xFF;
    ip6phdr_req.upper_layer_pkt_len[1] = (icmp_pkt_size >> 16) & 0xFF;
    ip6phdr_req.upper_layer_pkt_len[2] = (icmp_pkt_size >>  8) & 0xFF;
    ip6phdr_req.upper_layer_pkt_len[3] = icmp_pkt_size & 0xFF;
    ip6phdr_req.next_header[3] = ip6hdr_req.next_header;

    ip6hdr_req.payload = (uint8_t *)macgonuts_make_icmp_pkt(&icmphdr_req,
                                                            &icmp_pkt_size, &ip6phdr_req, sizeof(ip6phdr_req));
    if (ip6hdr_req.payload == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip6_epilogue;
    }
    ip6hdr_req.payload_length = icmp_pkt_size & 0xFFFF;

    ethfrm_req.data = (uint8_t *)macgonuts_make_ip6_pkt(&ip6hdr_req, &ethfrm_req.data_size);
    if (ethfrm_req.data == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip6_epilogue;
    }

    ns_pkt = macgonuts_make_ethernet_frm(&ethfrm_req, &ns_pkt_size);
    if (ns_pkt == NULL) {
        err = ENOMEM;
        goto get_ethaddr_ip6_epilogue;
    }

    do {
        if (macgonuts_sendpkt(rsk, ns_pkt, ns_pkt_size) == -1) {
            err = errno;
            continue;
        }

        na_pkt_size = macgonuts_recvpkt(rsk, na_pkt, sizeof(na_pkt));
        if (na_pkt_size == -1) {
            err = errno;
            continue;
        }

        macgonuts_release_ndp_nsna_hdr(&ndp_na_hdr);
        macgonuts_release_icmphdr(&icmphdr_rep);
        macgonuts_release_ip6hdr(&ip6hdr_rep);
        macgonuts_release_ethfrm(&ethfrm_rep);

        err = macgonuts_read_ethernet_frm(&ethfrm_rep, na_pkt, na_pkt_size);
        if (err != EXIT_SUCCESS
            || ethfrm_rep.ether_type != MACGONUTS_ETHER_TYPE_IP6
            || memcmp(ethfrm_rep.dest_hw_addr, ethfrm_req.src_hw_addr, sizeof(ethfrm_rep.dest_hw_addr)) != 0) {
            continue;
        }

        err = macgonuts_read_ip6_pkt(&ip6hdr_rep, ethfrm_rep.data, ethfrm_rep.data_size);
        if (err != EXIT_SUCCESS
            || memcmp(ip6hdr_rep.src_addr, unicast_dest_addr, sizeof(ip6hdr_rep.src_addr)) != 0
            || memcmp(ip6hdr_rep.dest_addr, ip6hdr_req.src_addr, sizeof(ip6hdr_rep.dest_addr)) != 0) {
            continue;
        }

        err = macgonuts_read_icmp_pkt(&icmphdr_rep, ip6hdr_rep.payload, (size_t)ip6hdr_rep.payload_length);
        if (err != EXIT_SUCCESS
            || icmphdr_rep.type != kNDPMsgTypeNeighborAdvertisement
            || icmphdr_rep.code != 0) {
            continue;
        }

        err = macgonuts_read_ndp_nsna_pkt(&ndp_na_hdr, icmphdr_rep.payload, icmphdr_rep.payload_size);
        if (err != EXIT_SUCCESS
            || (ndp_na_hdr.reserv & 0x2) != 0
            || memcmp(ndp_na_hdr.target_addr, ndp_ns_hdr.target_addr, sizeof(ndp_na_hdr.target_addr)) != 0
            || ndp_na_hdr.options == NULL
            || ndp_na_hdr.options_size != 8
            || ndp_na_hdr.options[0] != 0x02
            || ndp_na_hdr.options[1] != 0x01) {
            continue;
        }

        memcpy(hw_addr, &ndp_na_hdr.options[2], 6);
        err = EXIT_SUCCESS;
        done = 1;
    } while (!done && ntry-- > 0);

get_ethaddr_ip6_epilogue:

    if (ns_pkt != NULL) {
        free(ns_pkt);
        ns_pkt = NULL;
    }

    macgonuts_release_ndp_nsna_hdr(&ndp_ns_hdr);
    macgonuts_release_icmphdr(&icmphdr_req);
    macgonuts_release_ip6hdr(&ip6hdr_req);
    macgonuts_release_ethfrm(&ethfrm_req);

    macgonuts_release_ndp_nsna_hdr(&ndp_na_hdr);
    macgonuts_release_icmphdr(&icmphdr_rep);
    macgonuts_release_ip6hdr(&ip6hdr_rep);
    macgonuts_release_ethfrm(&ethfrm_rep);

    return err;
}

static int get_ethaddr_unk(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           const macgonuts_socket_t rsk, const char *iface) {
    macgonuts_si_error("layer3 address '%s' does not seem with a valid ipv4 or ipv6 address.\n", layer3addr);
    return EINVAL;
}
