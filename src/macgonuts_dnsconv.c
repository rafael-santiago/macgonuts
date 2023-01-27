/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_dnsconv.h>

static size_t get_u8str_total_size(const unsigned char *data, const size_t data_size, const size_t c_off,
                                   const int is_domain_name);

uint8_t *macgonuts_get_dns_u8str(const unsigned char *data, const size_t data_size,
                                 size_t *u8str_size, const size_t current_offset,
                                 const int is_domain_name) {
    const unsigned char *d = NULL;
    const unsigned char *d_end = NULL;
    uint8_t *u8str = NULL;
    uint8_t *u8p = NULL;
    uint8_t *u8p_end = NULL;

    if (u8str_size == NULL) {
        return NULL;
    }

    *u8str_size = 0;

    if (data == NULL || current_offset > data_size) {
        return NULL;
    }

    d = data;
    d_end = d + data_size;

    *u8str_size = get_u8str_total_size(data, data_size, current_offset, is_domain_name);

    if (*u8str_size == 0) {
        return NULL;
    }

    u8str = (uint8_t *)malloc(*u8str_size + 1);
    if (u8str == NULL) {
        *u8str_size = 0;
        return NULL;
    }
    memset(u8str, 0, *u8str_size + 1);

    d = data + current_offset;
    d_end = d + data_size - current_offset;
    u8p = u8str;
    u8p_end = u8p + *u8str_size;

    while (d >= (data - current_offset) && d < d_end && *d != 0 && u8p < u8p_end) {
        if ((*d & 0xC0) == 0) {
            memcpy(u8p, &d[1], d[0]);
            u8p += d[0];
            d += d[0] + 1;
            if (u8p >= u8p_end || d >= d_end) {
                continue;
            } else if (is_domain_name && *d != 0) {
                *u8p = '.';
                u8p++;
            }
        } else {
            if ((d + 1) >= d_end) {
                // INFO(Rafael): Double check to satisfy my professional paranoia! :)
                return 0;
            }
            d = &data[(uint16_t)(d[0] & 0x3F) << 8 | (uint16_t)d[1]];
        }
    }

    return u8str;
}

static size_t get_u8str_total_size(const unsigned char *data, const size_t data_size, const size_t c_off,
                                   const int is_domain_name) {
    const unsigned char *d = NULL;
    const unsigned char *d_end = NULL;
    size_t s = 0;

    if (c_off > data_size) {
        return 0;
    }

    d = data + c_off;
    d_end = d + data_size - c_off;

    while (d >= (data - c_off) && d < d_end && *d != 0) {
        if ((*d & 0xC0) == 0) {
            s += *d;
            d += *d + 1;
            if (is_domain_name && d < d_end && *d != 0) {
                s += 1; // INFO(Rafael): Plus one is for the dot symbol.
            }
        } else {
            if ((d + 1) >= d_end) {
                // INFO(Rafael): It seems malicious.
                return 0;
            }
            d = &data[((uint16_t)(d[0] & 0x3F) << 8 | (uint16_t)d[1])];
        }
    }

    return s;
}
