/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static int chk_ipv4_addr(const char *ip, const size_t ip_size);

static int chk_ipv6_addr(const char *ip, const size_t ip_size);

static int chk_ipvn_cidr(const size_t n, const char *addr, const size_t addr_size, const char *bits, const size_t bits_size);

static int chk_ipv4_cidr(const char *addr, const size_t addr_size, const char *bits, const size_t bits_size);

static int chk_ipv6_cidr(const char *addr, const size_t addr_size, const char *bits, const size_t bits_size);

static int is_int(const char *buf, const size_t buf_size);

int macgonuts_get_ip_version(const char *ip, const size_t ip_size) {
    if (chk_ipv4_addr(ip, ip_size)) {
        return 4;
    }
    if (chk_ipv6_addr(ip, ip_size)) {
        return 6;
    }
    return -1;
}

int macgonuts_check_ip_addr(const char *ip, const size_t ip_size) {
    int version = macgonuts_get_ip_version(ip, ip_size);
    return (version == 4 || version == 6);
}

int macgonuts_check_ip_cidr(const char *ip, const size_t ip_size) {
    char addr[128] = { 0 };
    size_t addr_size = 0;
    const char *ap = NULL;
    int is_valid = 0;
    if (ip == NULL || ip_size == 0) {
        return 0;
    }
    ap = strstr(ip, "/");
    if (ap == NULL) {
        return 0;
    }
    memcpy(addr, ip, (ap - ip) % (sizeof(addr) - 1));
    addr_size = strlen(addr);
    switch(macgonuts_get_ip_version(addr, addr_size)) {
        case 4:
            is_valid = chk_ipv4_cidr(addr, addr_size, ap + 1, strlen(ap + 1));
            break;

        case 6:
            is_valid = chk_ipv6_cidr(addr, addr_size, ap + 1, strlen(ap + 1));
            break;

        default:
            break;
    }
    return is_valid;
}

static int chk_ipv4_addr(const char *ip, const size_t ip_size) {
    const char *p = ip, *lp = p;
    const char *p_end = p + ip_size;
    size_t dots_nr = 0, octs_nr = 0;
    char num[4] = { 0 };
    int oct = 0;
    if (p == NULL) {
        return 0;
    }
    while (p < p_end) {
        if (*p == '.' || (p + 1) == p_end) {
            p += ((p + 1) == p_end);
            dots_nr += (*p == '.');
            if (lp == p || (p - lp) > 3 || dots_nr > 3) {
                return 0;
            }
            memset(num, 0, sizeof(num));
            memcpy(num, lp, p - lp);
            oct = atoi(num);
            if (oct < 0 || oct > 255) {
                return 0;
            }
            octs_nr++;
            lp = p + 1;
        }
        p++;
    }
    return (dots_nr == 3 && octs_nr == 4);
}

static int chk_ipv6_addr(const char *ip, const size_t ip_size) {
    const char *p = ip, *lp = p;
    const char *p_end = p + ip_size;
    char word[25] = { 0 };
    size_t w;
    long int u16_frac = 0;
    int is_valid = 0;
    int has_double_colon = 0;
    int double_colon_nr = 0;
    if (p == NULL) {
        return 0;
    }
    if (ip_size < 3 || (*p == ':' && p[1] != ':')) {
        return 0;
    }
    while (p < p_end) {
        if (*p == ':' || (p + 1) == p_end) {
            double_colon_nr += (*p == ':');
            p += ((p + 1) == p_end);
            if ((p - lp) > sizeof(word)) {
                return 0;
            }
            p += (lp == p);
            p += (isxdigit(*p) && (p + 1) < p_end && isxdigit(*(p + 1)));
            memset(word, 0, sizeof(word));
            memcpy(word, lp, p - lp);
            is_valid = 1;
            w = 0;
            do {
                is_valid = isxdigit(word[w++]);
            } while (is_valid && word[w] != 0);
            if(is_valid) {
                u16_frac = strtol(word, NULL, 16);
                if (u16_frac < 0 || u16_frac > 65535) {
                    return 0;
                }
            } else if (!is_valid && !has_double_colon) {
                is_valid = has_double_colon = (strcmp(word, ":") == 0);
            }
            if (!is_valid) {
                return 0;
            }
            lp = p + 1;
        }
        p++;
    }
    return (double_colon_nr > 0);
}

static int chk_ipvn_cidr(const size_t n, const char *addr, const size_t addr_size, const char *bits, const size_t bits_size) {
    int cidr_bits = 0;
    int (*chk_ipvn_addr)(const char *, const size_t) = (n == 4) ? chk_ipv4_addr : chk_ipv6_addr;
    if (chk_ipvn_addr(addr, addr_size) == 0) {
        return 0;
    }
    if (!is_int(bits, bits_size)) {
        return 0;
    }
    cidr_bits = atoi(bits);
    return (n == 4) ? (cidr_bits > 0 && cidr_bits < 31) : (cidr_bits > 0 && cidr_bits < 127);
}

static int chk_ipv4_cidr(const char *addr, const size_t addr_size, const char *bits, const size_t bits_size) {
    return chk_ipvn_cidr(4, addr, addr_size, bits, bits_size);
}

static int chk_ipv6_cidr(const char *addr, const size_t addr_size, const char *bits, const size_t bits_size) {
    return chk_ipvn_cidr(6, addr, addr_size, bits, bits_size);
}

static int is_int(const char *buf, const size_t buf_size) {
    const char *bp = buf;
    const char *bp_end = bp + buf_size;
    int is = 0;
    if (bp == NULL || buf_size == 0) {
        return 0;
    }
    do {
        is = isdigit(*bp);
        bp++;
    } while (!is && bp != bp_end);
    return is;
}
