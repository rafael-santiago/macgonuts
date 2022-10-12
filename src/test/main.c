/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cutest.h>
#include "macgonuts_etherconv_tests.h"
#include "macgonuts_socket_tests.h"
#include "macgonuts_ipconv_tests.h"
#include "macgonuts_ip6mcast_tests.h"
#include "macgonuts_ethfrm_tests.h"
#include "macgonuts_arphdr_tests.h"
#include "macgonuts_ip6hdr_tests.h"
#include "macgonuts_icmphdr_tests.h"
#include "macgonuts_ndphdr_tests.h"
#include "macgonuts_ipchsum_tests.h"
#include "macgonuts_get_ethaddr_tests.h"

CUTE_TEST_CASE(macgonuts_static_lib_tests)
    CUTE_RUN_TEST(macgonuts_check_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_get_raw_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_check_ip_addr_tests);
    CUTE_RUN_TEST(macgonuts_get_ip_version_tests);
    CUTE_RUN_TEST(macgonuts_check_ip_cidr_tests);
    CUTE_RUN_TEST(macgonuts_get_multicast_addr_tests);
    CUTE_RUN_TEST(macgonuts_get_unsolicited_multicast_addr_tests);
    CUTE_RUN_TEST(macgonuts_get_raw_ip_addr_tests);
    // INFO(Rafael): Those two ethernet conveniences depends on correctness of ip convenience module.
    CUTE_RUN_TEST(macgonuts_get_raw_ip6_mcast_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_get_raw_ip6_unsolicited_mcast_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_eval_ipchsum_tests);
    CUTE_RUN_TEST(macgonuts_read_ethernet_frm_tests);
    CUTE_RUN_TEST(macgonuts_make_ethernet_frm_tests);
    CUTE_RUN_TEST(macgonuts_read_arp_pkt_tests);
    CUTE_RUN_TEST(macgonuts_make_arp_pkt_tests);
    CUTE_RUN_TEST(macgonuts_read_ip6_pkt_tests);
    CUTE_RUN_TEST(macgonuts_make_ip6_pkt_tests);
    CUTE_RUN_TEST(macgonuts_read_icmp_pkt_tests);
    CUTE_RUN_TEST(macgonuts_make_icmp_pkt_tests);
    CUTE_RUN_TEST(macgonuts_read_ndp_nsna_pkt_tests);
    CUTE_RUN_TEST(macgonuts_make_ndp_nsna_pkt_tests);
    CUTE_RUN_TEST(macgonuts_getrandom_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_create_release_socket_tests);
    CUTE_RUN_TEST(macgonuts_set_iface_promisc_on_off_tests);
    CUTE_RUN_TEST(macgonuts_sendpkt_tests);
    CUTE_RUN_TEST(macgonuts_recvpkt_tests);
    CUTE_RUN_TEST(macgonuts_get_addr_from_iface_tests);
    CUTE_RUN_TEST(macgonuts_get_mac_from_iface_tests);
    //CUTE_RUN_TEST(macgonuts_get_ethaddr_ip6_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(macgonuts_static_lib_tests);
