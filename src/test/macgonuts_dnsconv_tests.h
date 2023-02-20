/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_DNSCONV_TESTS_H
#define MACGONUTS_TEST_MACGONUTS_DNSCONV_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_get_dns_u8str_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_get_qname_size_from_dname_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_make_label_from_domain_name_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_is_dnsreq_tests);

#endif // MACGONUTS_TEST_MACGONUTS_DNSCONV_TESTS_H
