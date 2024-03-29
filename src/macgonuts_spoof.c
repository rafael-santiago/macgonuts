/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_spoof.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_arphdr.h>
#include <macgonuts_ip6hdr.h>
#include <macgonuts_icmphdr.h>
#include <macgonuts_ndphdr.h>
#include <macgonuts_ip6mcast.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_socket.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_status_info.h>

static int macgonuts_get_spoof_layers_basic_info(const macgonuts_socket_t rsk,
                                                 struct macgonuts_spoof_layers_ctx *spf_layers,
                                                 const char *target_addr, const size_t target_addr_size,
                                                 const char *address2spoof, const size_t address2spoof_size,
                                                 const char *lo_iface);

static int macgonuts_spoof4(const macgonuts_socket_t rsk,
                            struct macgonuts_spoof_layers_ctx *spf_layers);

static int macgonuts_spoof6(const macgonuts_socket_t rsk,
                            struct macgonuts_spoof_layers_ctx *spf_layers);

static int macgonuts_spoof_err(const macgonuts_socket_t rsk,
                               struct macgonuts_spoof_layers_ctx *spf_layers);

int macgonuts_spoof(const macgonuts_socket_t rsk,
                    struct macgonuts_spoof_layers_ctx *spf_layers) {
    uint8_t ip_v = -1;
    int (*do_spoof)(const macgonuts_socket_t,
                    struct macgonuts_spoof_layers_ctx *) = NULL;
    int err = EFAULT;

    if (rsk == -1 || spf_layers == NULL) {
        return EINVAL;
    }

    ip_v = spf_layers->proto_addr_version;

    if ((ip_v != 4 && ip_v != 6) || spf_layers->proto_addr_size == 0) {
        return EPROTO;
    }

    do_spoof = (ip_v == 4) ? macgonuts_spoof4 :
               (ip_v == 6) ? macgonuts_spoof6 : macgonuts_spoof_err;

    err = do_spoof(rsk, spf_layers);

    if (spf_layers->always_do_pktcraft && spf_layers->spoof_frm != NULL) {
        // INFO(Rafael): For performance issues, in order to avoid executing everytime
        //               memory allocation tasks, the hardware address resolution packet
        //               is crafted once. Since more common tasks related to mac spoofing
        //               has well-defined targets, it is a big deal. However, macgonuts
        //               command line tool ships some anarchic features such as "mayhem"
        //               which in this case the spoof targets will vary a lot. For this
        //               case of spoofing task (being macgonuts as mac spoof engine) the
        //               always_do_pktcraft is also a big deal.
        free(spf_layers->spoof_frm);
        spf_layers->spoof_frm = NULL;
        spf_layers->spoof_frm_size = 0;
    }

    return err;
}

int macgonuts_undo_spoof(const macgonuts_socket_t rsk,
                         struct macgonuts_spoof_layers_ctx *spf_layers) {
    int err = EFAULT;
    unsigned char *swp_spoof_frm = NULL;
    size_t swp_spoof_frm_size = 0;
    uint8_t swp_hw_addr[6];
    if (spf_layers == NULL) {
        return EINVAL;
    }
    memcpy(&swp_hw_addr[0], &spf_layers->lo_hw_addr[0], sizeof(swp_hw_addr));
    memcpy(&spf_layers->lo_hw_addr[0], &spf_layers->spoof_hw_addr[0], sizeof(spf_layers->lo_hw_addr));
    swp_spoof_frm = spf_layers->spoof_frm;
    swp_spoof_frm_size = spf_layers->spoof_frm_size;
    spf_layers->spoof_frm = NULL;
    spf_layers->spoof_frm_size = 0;
    err = macgonuts_spoof(rsk, spf_layers);
    memcpy(&spf_layers->lo_hw_addr[0], &swp_hw_addr[0], sizeof(spf_layers->lo_hw_addr));
    spf_layers->spoof_frm = swp_spoof_frm;
    spf_layers->spoof_frm_size = swp_spoof_frm_size;
    swp_spoof_frm = NULL;
    return err;
}

void macgonuts_release_spoof_layers_ctx(struct macgonuts_spoof_layers_ctx *spf_layers) {
    if (spf_layers == NULL || spf_layers->spoof_frm == NULL) {
        return;
    }
    free(spf_layers->spoof_frm);
    spf_layers->spoof_frm = NULL;
    spf_layers->spoof_frm_size = 0;
}

int macgonuts_get_spoof_layers_info(const macgonuts_socket_t rsk,
                                    struct macgonuts_spoof_layers_ctx *spf_layers,
                                    const char *target_addr, const size_t target_addr_size,
                                    const char *address2spoof, const size_t address2spoof_size,
                                    const char *lo_iface) {
    int err = EFAULT;

    if (spf_layers == NULL
        || target_addr == NULL || target_addr_size == 0
        || address2spoof == NULL || address2spoof_size == 0
        || lo_iface == NULL
        || rsk == -1) {
        return EINVAL;
    }

    err = macgonuts_get_spoof_layers_basic_info(rsk,
                                                spf_layers,
                                                target_addr,
                                                target_addr_size,
                                                address2spoof,
                                                address2spoof_size,
                                                lo_iface);
    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_info_epilogue;
    }

    err = macgonuts_get_ethaddr(&spf_layers->tg_hw_addr[0],
                                sizeof(spf_layers->tg_hw_addr),
                                target_addr, target_addr_size,
                                rsk, lo_iface);

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_info_epilogue;
    }

    err = macgonuts_get_ethaddr(&spf_layers->spoof_hw_addr[0],
                                sizeof(spf_layers->spoof_hw_addr),
                                address2spoof, address2spoof_size,
                                rsk, lo_iface);

macgonuts_get_spoof_layers_info_epilogue:

    if (err != EXIT_SUCCESS && spf_layers != NULL) {
        memset(spf_layers, 0, sizeof(struct macgonuts_spoof_layers_ctx));
    }

    return err;
}

int macgonuts_get_spoof_layers_info_ex(const struct macgonuts_get_spoof_layers_info_ex_ctx *sk_info,
                                       const size_t sk_info_nr,
                                       struct macgonuts_spoof_layers_ctx *spf_layers,
                                       const char *target_addr, const size_t target_addr_size,
                                       const char *address2spoof, const size_t address2spoof_size,
                                       const char *lo_iface) {
    int err = EFAULT;
    const struct macgonuts_get_spoof_layers_info_ex_ctx *skp = NULL;
    const struct macgonuts_get_spoof_layers_info_ex_ctx *sk_info_end = NULL;

    if (sk_info == NULL
        || sk_info_nr == 0
        || spf_layers == NULL
        || target_addr == NULL
        || target_addr_size == 0
        || address2spoof == NULL
        || address2spoof_size == 0
        || lo_iface == NULL) {
        return EINVAL;
    }

    skp = sk_info;
    sk_info_end = skp + sk_info_nr;

    while (err != EXIT_SUCCESS
           && skp != sk_info_end) {
        if (sk_info->rsk == -1 || sk_info->iface == NULL) {
            return EINVAL;
        }
        err = macgonuts_get_spoof_layers_basic_info(sk_info->rsk,
                                                    spf_layers,
                                                    target_addr,
                                                    target_addr_size,
                                                    address2spoof,
                                                    address2spoof_size,
                                                    lo_iface);
        skp++;
    }

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_info_ex_epilogue;
    }

    skp = sk_info;
    err = EFAULT;

    while (err != EXIT_SUCCESS
           && skp != sk_info_end) {
        err = macgonuts_get_ethaddr(&spf_layers->tg_hw_addr[0],
                                    sizeof(spf_layers->tg_hw_addr),
                                    target_addr, target_addr_size,
                                    skp->rsk, skp->iface);
        skp++;
    }

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_info_ex_epilogue;
    }

    skp = sk_info;
    err = EFAULT;

    while (err != EXIT_SUCCESS
           && skp != sk_info_end) {
        err = macgonuts_get_ethaddr(&spf_layers->spoof_hw_addr[0],
                                    sizeof(spf_layers->spoof_hw_addr),
                                    address2spoof, address2spoof_size,
                                    skp->rsk, skp->iface);
        skp++;
    }

macgonuts_get_spoof_layers_info_ex_epilogue:

    if (err != EXIT_SUCCESS && spf_layers != NULL) {
        memset(spf_layers, 0, sizeof(struct macgonuts_spoof_layers_ctx));
    }

    return err;
}

static int macgonuts_get_spoof_layers_basic_info(const macgonuts_socket_t rsk,
                                                 struct macgonuts_spoof_layers_ctx *spf_layers,
                                                 const char *target_addr, const size_t target_addr_size,
                                                 const char *address2spoof, const size_t address2spoof_size,
                                                 const char *lo_iface) {
    char mac_buf[256] = "";
    char addr_buf[256] = "";
    int err = EFAULT;
    int ip_v[2] = { -1, -1 };

    spf_layers->spoof_frm = NULL;
    spf_layers->spoof_frm_size = 0;

    ip_v[0] = macgonuts_get_ip_version(target_addr, target_addr_size);
    ip_v[1] = macgonuts_get_ip_version(address2spoof, address2spoof_size);

    if (ip_v[0] == -1 || ip_v[1] == -1 || ip_v[0] != ip_v[1]) {
        macgonuts_si_error("network protocol version mismatch.\n");
        err = EPROTO;
        goto macgonuts_get_spoof_layers_basic_info_epilogue;
    }

    spf_layers->proto_addr_version = ip_v[0];

    spf_layers->proto_addr_size = (ip_v[0] == 4) ? 4
                                                 : 16;

    err = macgonuts_get_mac_from_iface(mac_buf, sizeof(mac_buf) - 1, lo_iface);

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_basic_info_epilogue;
    }

    err = macgonuts_get_raw_ether_addr(&spf_layers->lo_hw_addr[0],
                                       sizeof(spf_layers->lo_hw_addr),
                                       mac_buf, strlen(mac_buf));

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_basic_info_epilogue;
    }

    err = macgonuts_get_addr_from_iface(addr_buf,
                                        sizeof(addr_buf) - 1,
                                        ip_v[0], lo_iface);

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_basic_info_epilogue;
    }

    err = macgonuts_get_raw_ip_addr(spf_layers->lo_proto_addr,
                                    spf_layers->proto_addr_size,
                                    addr_buf, strlen(addr_buf));

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_basic_info_epilogue;
    }

    err = macgonuts_get_raw_ip_addr(spf_layers->tg_proto_addr,
                                    spf_layers->proto_addr_size,
                                    target_addr, target_addr_size);

    if (err != EXIT_SUCCESS) {
        goto macgonuts_get_spoof_layers_basic_info_epilogue;
    }

    err = macgonuts_get_raw_ip_addr(spf_layers->spoof_proto_addr,
                                    spf_layers->proto_addr_size,
                                    address2spoof, address2spoof_size);

macgonuts_get_spoof_layers_basic_info_epilogue:

    return err;
}

static int macgonuts_spoof4(const macgonuts_socket_t rsk,
                            struct macgonuts_spoof_layers_ctx *spf_layers) {
    struct macgonuts_ethfrm_ctx ethfrm;
    struct macgonuts_arphdr_ctx arphdr;

    memset(&ethfrm, 0, sizeof(ethfrm));
    memset(&arphdr, 0, sizeof(arphdr));

    if (spf_layers->spoof_frm == NULL || spf_layers->spoof_frm_size == 0) {
        assert(sizeof(ethfrm.dest_hw_addr) == sizeof(spf_layers->tg_hw_addr));
        assert(sizeof(ethfrm.src_hw_addr) == sizeof(spf_layers->lo_hw_addr));

        memcpy(&ethfrm.dest_hw_addr[0], &spf_layers->tg_hw_addr[0], sizeof(ethfrm.dest_hw_addr));
        memcpy(&ethfrm.src_hw_addr[0], &spf_layers->lo_hw_addr[0], sizeof(ethfrm.src_hw_addr));
        ethfrm.ether_type = MACGONUTS_ETHER_TYPE_ARP;

        arphdr.htype = MACGONUTS_ARP_HW_TYPE_ETHERNET;
        arphdr.ptype = MACGONUTS_ETHER_TYPE_IP4;
        arphdr.hlen = sizeof(ethfrm.dest_hw_addr);
        arphdr.plen = spf_layers->proto_addr_size;
        arphdr.oper = kARPOperReply;
        arphdr.sha = &spf_layers->lo_hw_addr[0];
        arphdr.spa = &spf_layers->spoof_proto_addr[0];
        arphdr.tha = &spf_layers->tg_hw_addr[0];
        arphdr.tpa = &spf_layers->tg_proto_addr[0];

        ethfrm.data = (uint8_t *)macgonuts_make_arp_pkt(&arphdr, &ethfrm.data_size);

        if (ethfrm.data == NULL) {
            return EFAULT;
        }

        spf_layers->spoof_frm = macgonuts_make_ethernet_frm(&ethfrm, &spf_layers->spoof_frm_size);
        arphdr.sha = NULL;
        arphdr.spa = NULL;
        arphdr.tha = NULL;
        arphdr.tpa = NULL;

        macgonuts_release_ethfrm(&ethfrm);
    }

    if (spf_layers->spoof_frm == NULL) {
        return ENOMEM;
    }

    if (macgonuts_sendpkt(rsk, spf_layers->spoof_frm, spf_layers->spoof_frm_size) != spf_layers->spoof_frm_size) {
        return EFAULT;
    }

    return EXIT_SUCCESS;
}

static int macgonuts_spoof6(const macgonuts_socket_t rsk,
                            struct macgonuts_spoof_layers_ctx *spf_layers) {
    struct macgonuts_ethfrm_ctx ethfrm;
    struct macgonuts_ip6hdr_ctx ip6hdr;
    struct macgonuts_ip6_pseudo_hdr_ctx ip6phdr;
    struct macgonuts_icmphdr_ctx icmphdr;
    struct macgonuts_ndp_nsna_hdr_ctx uns_na_hdr;
    int err = EFAULT;
    size_t icmp_pkt_size = 0;
    uint8_t release_memory = 0;

    memset(&ethfrm, 0, sizeof(ethfrm));
    memset(&ip6hdr, 0, sizeof(ip6hdr));
    memset(&ip6phdr, 0, sizeof(ip6phdr));
    memset(&icmphdr, 0, sizeof(icmphdr));
    memset(&uns_na_hdr, 0, sizeof(uns_na_hdr));

    if (spf_layers->spoof_frm == NULL || spf_layers->spoof_frm_size == 0) {
        assert(sizeof(ethfrm.dest_hw_addr) == sizeof(spf_layers->tg_hw_addr));
        assert(sizeof(ethfrm.src_hw_addr) == sizeof(spf_layers->lo_hw_addr));
        memcpy(&ethfrm.dest_hw_addr[0], &spf_layers->tg_hw_addr[0], sizeof(ethfrm.dest_hw_addr));
        memcpy(&ethfrm.src_hw_addr[0], &spf_layers->lo_hw_addr[0], sizeof(ethfrm.src_hw_addr));
        ethfrm.ether_type = MACGONUTS_ETHER_TYPE_IP6;

        ip6hdr.version = 6;
        ip6hdr.priority = 0;
        ip6hdr.flow_label = 0;
        ip6hdr.payload_length = 0;
        ip6hdr.next_header = 0x3A;
        ip6hdr.hop_limit = 0xFF;
        memcpy(&ip6hdr.src_addr[0], &spf_layers->spoof_proto_addr[0], sizeof(ip6hdr.src_addr));
        err = macgonuts_get_unsolicited_multicast_addr(&ip6hdr.dest_addr[0], sizeof(ip6hdr.dest_addr));
        if (err != EXIT_SUCCESS) {
            return err;
        }

        release_memory = 1;

        icmphdr.type = kNDPMsgTypeNeighborAdvertisement;
        icmphdr.code = 0;
        icmphdr.chsum = 0;

        uns_na_hdr.reserv = 0x20000000;
        memcpy(&uns_na_hdr.target_addr[0], &spf_layers->spoof_proto_addr[0], sizeof(uns_na_hdr.target_addr));
        uns_na_hdr.options_size = 2 + sizeof(spf_layers->lo_hw_addr);
        uns_na_hdr.options = (uint8_t *)malloc(uns_na_hdr.options_size);
        if (uns_na_hdr.options == NULL) {
            err = ENOMEM;
            goto macgonuts_spoof6_epilogue;
        }
        uns_na_hdr.options[0] = 0x02;
        uns_na_hdr.options[1] = 0x01;
        memcpy(&uns_na_hdr.options[2], &spf_layers->lo_hw_addr[0], sizeof(spf_layers->lo_hw_addr));

        icmphdr.payload = (uint8_t *)macgonuts_make_ndp_nsna_pkt(&uns_na_hdr, &icmphdr.payload_size);
        if (icmphdr.payload == NULL) {
            err = ENOMEM;
            goto macgonuts_spoof6_epilogue;
        }

        memcpy(&ip6phdr.src_addr[0], &ip6hdr.src_addr[0], sizeof(ip6phdr.src_addr));
        memcpy(&ip6phdr.dest_addr[0], &ip6hdr.dest_addr[0], sizeof(ip6phdr.dest_addr));
        icmp_pkt_size = 4 + icmphdr.payload_size;
        ip6phdr.upper_layer_pkt_len[0] = (icmp_pkt_size >> 24) & 0xFF;
        ip6phdr.upper_layer_pkt_len[1] = (icmp_pkt_size >> 16) & 0xFF;
        ip6phdr.upper_layer_pkt_len[2] = (icmp_pkt_size >>  8) & 0xFF;
        ip6phdr.upper_layer_pkt_len[3] = icmp_pkt_size & 0xFF;
        ip6phdr.next_header[3] = ip6hdr.next_header;

        ip6hdr.payload = (uint8_t *)macgonuts_make_icmp_pkt(&icmphdr, &icmp_pkt_size, &ip6phdr, sizeof(ip6phdr));
        if (ip6hdr.payload == NULL) {
            err = ENOMEM;
            goto macgonuts_spoof6_epilogue;
        }

        ip6hdr.payload_length = icmp_pkt_size & 0xFFFF;

        ethfrm.data = (uint8_t *)macgonuts_make_ip6_pkt(&ip6hdr, &ethfrm.data_size);
        if (ethfrm.data == NULL) {
            err = ENOMEM;
            goto macgonuts_spoof6_epilogue;
        }

        spf_layers->spoof_frm = macgonuts_make_ethernet_frm(&ethfrm, &spf_layers->spoof_frm_size);
    }

    if (spf_layers->spoof_frm == NULL) {
        err = ENOMEM;
        goto macgonuts_spoof6_epilogue;
    }

    if (macgonuts_sendpkt(rsk, spf_layers->spoof_frm, spf_layers->spoof_frm_size) == spf_layers->spoof_frm_size) {
        err = EXIT_SUCCESS;
    } else {
        err = EFAULT;
    }

macgonuts_spoof6_epilogue:

    if (release_memory) {
        macgonuts_release_ndp_nsna_hdr(&uns_na_hdr);
        macgonuts_release_icmphdr(&icmphdr);
        macgonuts_release_ip6hdr(&ip6hdr);
        macgonuts_release_ethfrm(&ethfrm);
    }

    return err;
}

static int macgonuts_spoof_err(const macgonuts_socket_t rsk,
                               struct macgonuts_spoof_layers_ctx *spf_layers) {
    macgonuts_si_error("there is no spoofing support for the supplied addresses, check them and try again.\n");
    return ENOTSUP;
}
