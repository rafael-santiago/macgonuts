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
#include <macgonuts_etherconv.h>
#include <macgonuts_socket.h>
#include <assert.h>

typedef int (*get_ethaddr_handler_func)(uint8_t *hw_addr, const size_t hw_addr_size,
                                        const char *layer3addr, const size_t layer3addr_size,
                                        macgonuts_socket_t rsk, const char *iface);

static int get_ethaddr_ip4(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           macgonuts_socket_t rsk, const char *iface);

static int get_ethaddr_ip6(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           macgonuts_socket_t rsk, const char *iface);

static int get_ethaddr_unk(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           macgonuts_socket_t rsk, const char *iface);

int macgonuts_get_ethaddr(uint8_t *hw_addr, const size_t hw_addr_size,
                          const char *layer3addr, const size_t layer3addr_size,
                          macgonuts_socket_t rsk, const char *iface) {
    get_ethaddr_handler_func get_ethaddr = NULL;
    int l3addr_version = 0;

    if (hw_addr == NULL || hw_addr_size != 6 || layer3addr != NULL || layer3addr_size == 0) {
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
                           macgonuts_socket_t rsk, const char *iface) {
    int err = EFAULT;
    struct macgonuts_ethfrm_ctx ethfrm = { 0 };
    struct macgonuts_arphdr_ctx arp_req_hdr = { 0 }, arp_rep_hdr = { 0 };
    char src_hw_addr[20] = { 0 };
    char src_ip_addr[20] = { 0 };
    int ntry = 10;
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
    arp_req_hdr.ptype = MACGONUTS_ETHER_TYPE_IP;
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
    if (macgonuts_get_raw_ip_addr(arp_req_hdr.spa, arp_req_hdr.plen, src_ip_addr, sizeof(src_ip_addr)) != EXIT_SUCCESS
        || macgonuts_get_raw_ip_addr(arp_req_hdr.tpa, arp_req_hdr.plen, layer3addr, layer3addr_size) != EXIT_SUCCESS) {
        err = EINVAL;
        goto get_ethaddr_ip4_epilogue;
    }
    assert(sizeof(arp_req_hdr.sha) == sizeof(ethfrm.src_hw_addr));
    memcpy(arp_req_hdr.sha, ethfrm.src_hw_addr, sizeof(arp_req_hdr.sha));
    memset(arp_req_hdr.tha, 0, sizeof(arp_req_hdr.tha));
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
    do {
        bytes_nr = macgonuts_sendpkt(rsk, arp_req_pkt, arp_req_pkt_size);
        if (bytes_nr == -1) {
            err = errno;
            continue;
        }
        bytes_nr = macgonuts_recvpkt(rsk, arp_rep_pkt, arp_rep_pkt_size);
        err = macgonuts_read_ethernet_frm(&ethfrm, arp_rep_pkt, arp_rep_pkt_size);
        if (err != EXIT_SUCCESS
            || ethfrm.ether_type != MACGONUTS_ETHER_TYPE_ARP) {
            continue;
        }
        err = macgonuts_read_arp_pkt(&arp_rep_hdr, ethfrm.data, ethfrm.data_size);
        if (err != EXIT_SUCCESS
            || arp_rep_hdr.oper != kARPOperReply
            || memcmp(arp_rep_hdr.spa, arp_req_hdr.tpa, sizeof(arp_rep_hdr.tpa)) != 0
            || memcmp(arp_req_hdr.tpa, arp_req_hdr.spa, sizeof(arp_rep_hdr.spa)) != 0) {
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
                           macgonuts_socket_t rsk, const char *iface) {
    return ENOENT;
}

static int get_ethaddr_unk(uint8_t *hw_addr, const size_t hw_addr_size,
                           const char *layer3addr, const size_t layer3addr_size,
                           macgonuts_socket_t rsk, const char *iface) {
    fprintf(stderr, "error: layer3 address '%s' does not seem with a valid ipv4 or ipv6 address.\n");
    return EINVAL;
}
