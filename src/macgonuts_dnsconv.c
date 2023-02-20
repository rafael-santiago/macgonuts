/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_dnsconv.h>
#include <macgonuts_ethfrm.h>

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

size_t macgonuts_get_qname_size_from_dname(const uint8_t *dname, const size_t dname_size) {
    const uint8_t *d = NULL;
    const uint8_t *d_end = NULL;
    const uint8_t *ld = NULL;
    size_t qsize = 1;
    size_t sec_size = 0;

    if (dname == NULL || dname_size == 0) {
        return 0;
    }

    d = ld = dname;
    d_end = d + dname_size;

    while (d != d_end) {
        if (*d == '.' || (d + 1) == d_end) {
            sec_size = (d - ld);
            if (sec_size > 255) {
                return 0;
            }
            qsize += sec_size + 1;
            ld = d + 1;
        }
        d++;
    }

    return qsize;
}

uint8_t *macgonuts_make_label_from_domain_name(const uint8_t *domain_name,
                                               const size_t domain_name_size,
                                               size_t *label_size) {
    uint8_t *label = NULL;
    uint8_t *lp = NULL;
    const uint8_t *d_name = domain_name;
    const uint8_t *d_name_end = d_name + domain_name_size;
    const uint8_t *ld_name = d_name;

    if (domain_name == NULL || domain_name_size == 0 || label_size == NULL) {
        return NULL;
    }

    *label_size = macgonuts_get_qname_size_from_dname(domain_name, domain_name_size);

    if (*label_size > 0) {
        label = (uint8_t *)malloc(*label_size);
        if (label == NULL) {
            *label_size = 0;
            return NULL;
        }
        lp = label;
        while (d_name != d_name_end) {
            if (*d_name == '.' || (d_name + 1) == d_name_end) {
                lp[0] = (d_name - ld_name) + (*d_name != '.');
                memcpy(&lp[1], ld_name, lp[0]);
                lp += lp[0] + 1;
                ld_name = d_name + 1;
            }
            d_name++;
        }
    }

    return label;
}

int macgonuts_is_dnsreq(const unsigned char *ethfrm, const size_t ethfrm_size) {
    const unsigned char *ep = NULL;
    const unsigned char *ep_end = NULL;
    uint16_t u16;

    if (ethfrm == NULL || ethfrm_size == 0) {
        return 0;
    }

    ep = ethfrm;
    ep_end = ep + ethfrm_size;

    if ((ep + 14) >= ep_end) {
        return 0;
    }

    ep += 12;
    u16 = (uint16_t)ep[0] << 8 | (uint16_t)ep[1];
    ep += 2;

    switch (u16) {
        case MACGONUTS_ETHER_TYPE_IP4:
            ep += 9;
            break;

        case MACGONUTS_ETHER_TYPE_IP6:
            ep += 6;
            break;

        default:
            return 0;
    }

    if (ep >= ep_end || *ep != 0x11) {
        // INFO(Rafael): Only considering DNS packets wrapped into UDP.
        return 0;
    }

    ep = (ethfrm + 14) + ((u16 == MACGONUTS_ETHER_TYPE_IP4) ? (4 * ((ep[-9]) & 0x0F)) : 40);

    if ((ep + 8) >= ep_end) {
        return 0;
    }

    u16 = (uint16_t)ep[2] << 8 | (uint16_t)ep[3];

    return (u16 == 53);
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
