/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_DNSCONV_H
#define MACGONUTS_DNSCONV_H 1

#include <macgonuts_types.h>

uint8_t *macgonuts_get_dns_u8str(const unsigned char *data, const size_t data_size,
                                 size_t *u8str_size, const size_t current_offset, const int is_domain_name);

size_t macgonuts_get_qname_size_from_dname(const uint8_t *dname, const size_t dname_size);

uint8_t *macgonuts_make_label_from_domain_name(const uint8_t *domain_name,
                                               const size_t domain_name_size,
                                               size_t *label_size);

#endif // MACGONUTS_DNSCONV_H
