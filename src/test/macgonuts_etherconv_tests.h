/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_MACGONUTS_ETHERCONV_TESTS_H
#define MACGONUTS_MACGONUTS_ETHERCONV_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_check_ether_addr_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_getrandom_ether_addr_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_raw_ether_addr_tests);

#endif // MACGONUTS_MACGONUTS_ETHERCONV_TESTS_H

