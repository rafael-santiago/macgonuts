/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_IPCONV_H
#define MACGONUTS_IPCONV_H 1

#include <macgonuts_types.h>

int macgonuts_get_ip_version(const char *ip, const size_t ip_size);

int macgonuts_check_ip_addr(const char *ip, const size_t ip_size);

int macgonuts_check_ip_cidr(const char *ip, const size_t ip_size);

#endif // MACGONUTS_IPCONV_H

