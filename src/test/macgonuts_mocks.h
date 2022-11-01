/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_MOCKS_H
#define MACGONUTS_TEST_MACGONUTS_MOCKS_H 1

// WARN(Rafael): Personally I hate this kind of shit, on testing my stuff,
//               but here it is a "necessary evil".

#include <stdlib.h>

void mock_set_expected_ip_version(const int version);

void mock_set_expected_ip4_addr(const char *addr);

void mock_set_expected_ip6_addr(const char *addr);

void mock_set_recv_buf(const unsigned char *buf, const size_t buf_size);

unsigned char *mock_get_send_buf(size_t *buf_size);

#endif
