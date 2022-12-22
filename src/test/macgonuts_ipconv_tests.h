/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_IPCONV_H
#define MACGONUTS_TEST_MACGONUTS_IPCONV_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_get_ip_version_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_check_ip_addr_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_check_ip_cidr_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_raw_ip_addr_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_raw_cidr_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_raw_ip2literal_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_inc_raw_ip_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_cidr_version_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_last_net_addr_tests);

#endif // MACGONUTS_TEST_MACGONUTS_IPCONV_H

