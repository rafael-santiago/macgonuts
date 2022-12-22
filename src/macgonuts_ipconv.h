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

int macgonuts_get_cidr_version(const char *ip, const size_t ip_size);

int macgonuts_check_ip_addr(const char *ip, const size_t ip_size);

int macgonuts_check_ip_cidr(const char *ip, const size_t ip_size);

int macgonuts_get_raw_ip_addr(uint8_t *raw, const size_t raw_max_size, const char *ip, const size_t ip_size);

int macgonuts_get_raw_cidr(uint8_t *first_addr, uint8_t *last_addr, const char *cidr, const size_t cidr_size);

int macgonuts_get_last_net_addr(uint8_t *last, const char *cidr, const size_t cidr_size);

int macgonuts_raw_ip2literal(char *out, const size_t max_out, const uint8_t *raw, const size_t raw_size);

void macgonuts_inc_raw_ip(uint8_t *raw, const size_t raw_size);

#endif // MACGONUTS_IPCONV_H

