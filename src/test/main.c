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

CUTE_TEST_CASE(macgonuts_static_lib_tests)
    CUTE_RUN_TEST(macgonuts_check_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_check_ip_addr_tests);
    CUTE_RUN_TEST(macgonuts_get_ip_version_tests);
    CUTE_RUN_TEST(macgonuts_check_ip_cidr_tests);
    CUTE_RUN_TEST(macgonuts_getrandom_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_create_release_socket_tests);
    CUTE_RUN_TEST(macgonuts_sendpkt_tests);
    CUTE_RUN_TEST(macgonuts_recvpkt_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(macgonuts_static_lib_tests);
