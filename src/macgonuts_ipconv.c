/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ipconv.h>

static int chk_ipv4_addr(const char *ip, const size_t ip_size);

static int chk_ipv6_addr(const char *ip, const size_t ip_size);

static int chk_ipvn_cidr(const size_t n, const char *addr, const size_t addr_size,
                         const char *bits, const size_t bits_size);

static int chk_ipv4_cidr(const char *addr, const size_t addr_size, const char *bits, const size_t bits_size);

static int chk_ipv6_cidr(const char *addr, const size_t addr_size, const char *bits, const size_t bits_size);

static int is_int(const char *buf, const size_t buf_size);

static int get_raw_ip4(uint8_t *raw, const size_t raw_max_size, const char *ip, const size_t ip_size);

static int get_raw_ip6(uint8_t *raw, const size_t raw_max_size, const char *ip, const size_t ip_size);

static int get_raw_cidr4(uint8_t *first_raw, uint8_t *last_raw,
                         const char *ip, const size_t ip_size, size_t cidr_net_bitsize);

static int get_raw_cidr6(uint8_t *first_raw, uint8_t *last_raw,
                         const char *ip, const size_t ip_size, size_t cidr_net_bitsize);

static int raw_ip2literal_4(char *out, const size_t max_out, const uint8_t *raw, const size_t raw_size);

static int raw_ip2literal_6(char *out, const size_t max_out, const uint8_t *raw, const size_t raw_size);

static int get_last_net_addr4(uint8_t *last, const char *cidr_addr, const size_t cidr_addr_size,
                              const size_t cidr_net_bitsize);

static int get_last_net_addr6(uint8_t *last, const char *cidr_addr, const size_t cidr_addr_size,
                              const size_t cidr_net_bitsize);

int macgonuts_get_raw_ip_addr(uint8_t *raw, const size_t raw_max_size, const char *ip, const size_t ip_size) {
    int version = 0;
    if (raw == NULL || raw_max_size == 0 || ip == NULL || ip_size == 0) {
        return EINVAL;
    }
    version = macgonuts_get_ip_version(ip, ip_size);
    if (version == -1) {
        return EINVAL;
    }
    return (version == 4) ? get_raw_ip4(raw, raw_max_size, ip, ip_size) :
                            get_raw_ip6(raw, raw_max_size, ip, ip_size);
}

int macgonuts_get_ip_version(const char *ip, const size_t ip_size) {
    if (chk_ipv4_addr(ip, ip_size)) {
        return 4;
    }
    if (chk_ipv6_addr(ip, ip_size)) {
        return 6;
    }
    return -1;
}

int macgonuts_get_cidr_version(const char *ip, const size_t ip_size) {
    char addr[128] = { 0 };
    size_t addr_size = 0;
    const char *slash = NULL;

    if (ip == NULL || ip_size == 0 || !macgonuts_check_ip_cidr(ip, ip_size)) {
        return -1;
    }

    slash = strstr(ip, "/");
    addr_size = (slash - ip);
    memcpy(addr, ip, addr_size);

    if (chk_ipv4_addr(addr, addr_size)) {
        return 4;
    }

    if (chk_ipv6_addr(addr, addr_size)) {
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

int macgonuts_get_raw_cidr(uint8_t *first_addr, uint8_t *last_addr, const char *cidr, const size_t cidr_size) {
    int err = EFAULT;
    char *slash_p = NULL;
    char cidr_addr[128] = { 0 };
    size_t cidr_addr_size = 0;
    size_t cidr_net_bitsize = 0;
    if (first_addr == NULL
        || last_addr == NULL
        || cidr == NULL
        || cidr_size == 0
        || !macgonuts_check_ip_cidr(cidr, cidr_size)) {
        return EINVAL;
    }
    slash_p = strstr(cidr, "/");
    cidr_addr_size = (slash_p - cidr) % sizeof(cidr_addr);
    memcpy(cidr_addr, cidr, cidr_addr_size);
    cidr_net_bitsize = atoi(slash_p + 1);
    switch (macgonuts_get_ip_version(cidr_addr, cidr_addr_size)) {
        case 4:
            err = get_raw_cidr4(first_addr, last_addr, cidr_addr, cidr_addr_size, cidr_net_bitsize);
            break;

        case 6:
            err = get_raw_cidr6(first_addr, last_addr, cidr_addr, cidr_addr_size, cidr_net_bitsize);
            break;

        default:
            err = EINVAL; // INFO(Rafael): It should never happen in normal conditions.
            break;
    }

    return err;
}

int macgonuts_get_last_net_addr(uint8_t *last, const char *cidr, const size_t cidr_size) {
    size_t cidr_addr_size;
    char cidr_addr[128] = { 0 };
    const char *slash = NULL;
    size_t cidr_net_bitsize = 0;
    int err = EFAULT;

    if (last == NULL
        || cidr == NULL
        || cidr_size == 0
        || !macgonuts_check_ip_cidr(cidr, cidr_size)) {
        return EINVAL;
    }

    slash = strstr(cidr, "/");
    cidr_addr_size = (slash - cidr) % sizeof(cidr_addr);
    memcpy(cidr_addr, cidr, cidr_addr_size % sizeof(cidr_addr));
    cidr_net_bitsize = atoi(slash + 1);

    switch (macgonuts_get_ip_version(cidr_addr, cidr_addr_size)) {
        case 4:
            err = get_last_net_addr4(last, cidr_addr, cidr_addr_size, cidr_net_bitsize);
            break;

        case 6:
            err = get_last_net_addr6(last, cidr_addr, cidr_addr_size, cidr_net_bitsize);
            break;

        default:
            err = EINVAL; // INFO(Rafael): It should never happen in normal conditions.
            break;
    }

    return err;
}

int macgonuts_raw_ip2literal(char *out, const size_t max_out, const uint8_t *raw, const size_t raw_size) {
    int (*raw_ip2literal)(char *, const size_t, const uint8_t *, const size_t) = NULL;
    if (out == NULL || max_out == 0 || raw == NULL || !(raw_size == 4 || raw_size == 16)) {
        return EINVAL;
    }
    raw_ip2literal = (raw_size == 4) ? raw_ip2literal_4 : raw_ip2literal_6;
    return raw_ip2literal(out, max_out, raw, raw_size);
}

void macgonuts_inc_raw_ip(uint8_t *raw, const size_t raw_size) {
    uint8_t *rp_end = raw - 1;
    uint8_t *rp = (rp_end + 1) + raw_size - 1;
    uint8_t cf;
    uint8_t t = *rp;
    *rp += 1;
    cf = (*rp < t);
    rp--;
    while (rp != rp_end) {
        t = *rp;
        *rp += cf;
        cf = (*rp < t);
        rp--;
    }
}

int macgonuts_addrs_from_same_network(const uint8_t *addr_a, const uint8_t *addr_b,
                                      const uint8_t *netmask, const int ip_version) {
    size_t addr_size;
    uint8_t mask[2][16] = { 0 };
    const uint8_t *ap = NULL;
    const uint8_t *ap_end = NULL;
    const uint8_t *np = NULL;
    uint8_t *mp = NULL;
    const uint8_t *addrs[2] = { addr_a, addr_b };
    size_t a;

    if (addr_a == NULL || addr_b == NULL || netmask == NULL || (ip_version != 4 && ip_version != 6)) {
        return 0;
    }

    addr_size = (ip_version == 4) ? 4 : 16;

    for (a = 0; a < 2; a++) {
        ap = addrs[a];
        ap_end = ap + addr_size;
        np = &netmask[0];
        mp = &mask[a][0];
        while (ap != ap_end) {
            *mp = *ap & *np;
            ap++;
            np++;
            mp++;
        }
    }

    return (memcmp(&mask[0], &mask[1], addr_size) == 0);
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
            if (!is_int(lp, p - lp)) {
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
    const char *p = ip;
    const char *p_end = p + ip_size;
    const char *lp = NULL;
    int has_double_colon = 0;
    char word[10] = { 0 };
    long int u16_frac = 0;
    int is_double_colon = 0;

    if (strstr(ip, ":") == NULL) {
        return 0;
    }

    if (ip[0] == ':' && ip_size < 3) {
        return 0;
    }

    if (ip[0] == ':' && ip_size > 3 && ip[1] != ':') {
        return 0;
    }

    while (p != p_end) {
        switch (*p) {
            case ':':
                is_double_colon = ((p + 1) < p_end && p[1] == ':');
                if (is_double_colon && has_double_colon) {
                    return 0;
                } else if (is_double_colon) {
                    has_double_colon = is_double_colon;
                }
                p += has_double_colon;
                break;

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                lp = p;
                while (isxdigit(*p) && p != p_end) {
                    p++;
                }
                memset(word, 0, sizeof(word));
                memcpy(word, lp, (p - lp) % sizeof(word));
                u16_frac = strtol(word, NULL, 16);
                if (u16_frac < 0 || u16_frac > 65535) {
                    return 0;
                }
                p--;
                break;

            default:
                return 0;
        }
        p++;
    }

    return 1;
}

static int chk_ipvn_cidr(const size_t n, const char *addr, const size_t addr_size,
                         const char *bits, const size_t bits_size) {
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
    } while (is && bp != bp_end);
    return is;
}

static int get_raw_ip4(uint8_t *raw, const size_t raw_max_size, const char *ip, const size_t ip_size) {
    const char *i = NULL;
    const char *i_end = NULL;
    const char *op = NULL;
    uint8_t *rp = NULL;
    char oc[4] = { 0 };
    if (raw_max_size < 4) {
        return ERANGE;
    }
    i = op = ip;
    i_end = i + ip_size;
    rp = raw;
    while (i < i_end && rp < (raw + raw_max_size)) {
        if (*i == '.' || (i + 1) == i_end) {
            i += ((i + 1) == i_end);
            memset(oc, 0, sizeof(oc));
            if ((i - op) > sizeof(oc)) {
                return ENOBUFS;
            }
            memcpy(oc, op, i - op);
            *rp = atoi(oc);
            op = i + 1;
            rp++;
        }
        i++;
    }
    return EXIT_SUCCESS;
}

static int get_raw_ip6(uint8_t *raw, const size_t raw_max_size, const char *ip, const size_t ip_size) {
    const char *i = NULL, *ii = NULL;
    const char *i_end = NULL;
    const char *op = NULL;
    uint8_t *rp = NULL;
    uint16_t u16 = 0;
    size_t dcolon_nr = 0;
    int nibbles_nr = 0;
    if (raw_max_size < 16) {
        return ERANGE;
    }
    i = op = ip;
    i_end = i + ip_size;
    rp = raw;
    while (i < i_end && rp < (raw + raw_max_size)) {
        switch (i[0]) {
            case ':':
                op = i + 1;
                if ((i + 1) != i_end && i[1] == ':') {
                    i++;
                    ii = i;
                    while (ii != i_end) {
                        dcolon_nr += (*ii == ':');
                        ii++;
                    }
                    dcolon_nr = 16 - ((rp - raw) + (dcolon_nr << 1));
                    while (dcolon_nr > 0 && rp != (raw + raw_max_size)) {
                        *rp = 0;
                        rp++;
                        dcolon_nr--;
                    }
                    op += 1;
                }
                break;

            default:
#define nib2num(n) ( isdigit((n)) ? ((n) - 48) : (toupper((n)) - 55) )
                u16 = (u16 << 4) | nib2num(i[0]);
                nibbles_nr++;
                if (((i + 1) < i_end && i[-1] == ':' && i[1] == ':') || (i + 1) == i_end
                    || ((i + 1) < i_end && i[1] == ':' && (i + 2) != i_end && i[2] != ':' && nibbles_nr > 2)) {
                    nibbles_nr = 4;
                }
#undef nibnum
                if (nibbles_nr == 4) {
                    rp[0] = (u16 >> 8) & 0xFF;
                    rp[1] = u16 & 0xFF;
                    rp += 2;
                    u16 = 0;
                    nibbles_nr = 0;
                }
                break;
        }
        i++;
    }
    return EXIT_SUCCESS;
}

static int get_raw_cidr4(uint8_t *first_raw, uint8_t *last_raw,
                         const char *ip, const size_t ip_size, size_t cidr_net_bitsize) {
    uint32_t mask = 0xFFFFFFFF >> cidr_net_bitsize;
    uint8_t raw_ip[4] = { 0 };
    uint32_t ip_addr = 0;
    int err = macgonuts_get_raw_ip_addr(raw_ip, sizeof(raw_ip), ip, ip_size);
    if (err != EXIT_SUCCESS) {
        return err;
    }
    ip_addr = (uint32_t)raw_ip[0] << 24 |
              (uint32_t)raw_ip[1] << 16 |
              (uint32_t)raw_ip[2] <<  8 |
              (uint32_t)raw_ip[3];
    ip_addr = ip_addr & (~mask);
    first_raw[0] = (ip_addr >> 24) & 0xFF;
    first_raw[1] = (ip_addr >> 16) & 0xFF;
    first_raw[2] = (ip_addr >>  8) & 0xFF;
    first_raw[3] = ip_addr & 0xFF;
    ip_addr = ip_addr | mask;
    last_raw[0] = (ip_addr >> 24) & 0xFF;
    last_raw[1] = (ip_addr >> 16) & 0xFF;
    last_raw[2] = (ip_addr >>  8) & 0xFF;
    last_raw[3] = ip_addr & 0xFF;
    return EXIT_SUCCESS;
}

static void shiftr128b(uint32_t *value, const size_t n) {
    unsigned char b0 = 0;
    unsigned char b1 = 0;
    size_t c;
    for (c = 0;  c < n; c++) {
        b0 = value[0] & 1;
        value[0] = (value[0] >> 1);
        b1 = value[1] & 1;
        value[1] = ((uint32_t)b0 << 31) | (value[1] >> 1);
        b0 = value[2] & 1;
        value[2] = ((uint32_t)b1 << 31) | (value[2] >> 1);
        b1 = value[3] & 1;
        value[3] = ((uint32_t)b0 << 31) | (value[3] >> 1);
    }
}

static int get_raw_cidr6(uint8_t *first_raw, uint8_t *last_raw,
                         const char *ip, const size_t ip_size, size_t cidr_net_bitsize) {
    uint32_t mask[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    uint8_t raw_ip[16] = { 0 };
    uint32_t ip_addr[4] = { 0 };
    int err = macgonuts_get_raw_ip_addr(raw_ip, sizeof(raw_ip), ip, ip_size);
    if (err != EXIT_SUCCESS) {
        return err;
    }
    ip_addr[0] = ((uint32_t)raw_ip[ 0] << 24) |
                 ((uint32_t)raw_ip[ 1] << 16) |
                 ((uint32_t)raw_ip[ 2] <<  8) |
                 ((uint32_t)raw_ip[ 3]);
    ip_addr[1] = ((uint32_t)raw_ip[ 4] << 24) |
                 ((uint32_t)raw_ip[ 5] << 16) |
                 ((uint32_t)raw_ip[ 6] <<  8) |
                 ((uint32_t)raw_ip[ 7]);
    ip_addr[2] = ((uint32_t)raw_ip[ 8] << 24) |
                 ((uint32_t)raw_ip[ 9] << 16) |
                 ((uint32_t)raw_ip[10] << 8)  |
                 ((uint32_t)raw_ip[11]);
    ip_addr[3] = ((uint32_t)raw_ip[12] << 24) |
                 ((uint32_t)raw_ip[13] << 16) |
                 ((uint32_t)raw_ip[14] <<  8) |
                 ((uint32_t)raw_ip[15]);
    shiftr128b(mask, cidr_net_bitsize);
    ip_addr[0] = ip_addr[0] & (~mask[0]);
    ip_addr[1] = ip_addr[1] & (~mask[1]);
    ip_addr[2] = ip_addr[2] & (~mask[2]);
    ip_addr[3] = ip_addr[3] & (~mask[3]);
    first_raw[ 0] = (ip_addr[ 0] >> 24) & 0xFF;
    first_raw[ 1] = (ip_addr[ 0] >> 16) & 0xFF;
    first_raw[ 2] = (ip_addr[ 0] >>  8) & 0xFF;
    first_raw[ 3] =  ip_addr[ 0] & 0xFF;
    first_raw[ 4] = (ip_addr[ 1] >> 24) & 0xFF;
    first_raw[ 5] = (ip_addr[ 1] >> 16) & 0xFF;
    first_raw[ 6] = (ip_addr[ 1] >>  8) & 0xFF;
    first_raw[ 7] =  ip_addr[ 1] & 0xFF;
    first_raw[ 8] = (ip_addr[ 2] >> 24) & 0xFF;
    first_raw[ 9] = (ip_addr[ 2] >> 16) & 0xFF;
    first_raw[10] = (ip_addr[ 2] >>  8) & 0xFF;
    first_raw[11] =  ip_addr[ 2] & 0xFF;
    first_raw[12] = (ip_addr[ 3] >> 24) & 0xFF;
    first_raw[13] = (ip_addr[ 3] >> 16) & 0xFF;
    first_raw[14] = (ip_addr[ 3] >>  8) & 0xFF;
    first_raw[15] =  ip_addr[ 3] & 0xFF;
    ip_addr[0] = ip_addr[0] | mask[0];
    ip_addr[1] = ip_addr[1] | mask[1];
    ip_addr[2] = ip_addr[2] | mask[2];
    ip_addr[3] = ip_addr[3] | mask[3];
    last_raw[ 0] = (ip_addr[ 0] >> 24) & 0xFF;
    last_raw[ 1] = (ip_addr[ 0] >> 16) & 0xFF;
    last_raw[ 2] = (ip_addr[ 0] >>  8) & 0xFF;
    last_raw[ 3] =  ip_addr[ 0] & 0xFF;
    last_raw[ 4] = (ip_addr[ 1] >> 24) & 0xFF;
    last_raw[ 5] = (ip_addr[ 1] >> 16) & 0xFF;
    last_raw[ 6] = (ip_addr[ 1] >>  8) & 0xFF;
    last_raw[ 7] =  ip_addr[ 1] & 0xFF;
    last_raw[ 8] = (ip_addr[ 2] >> 24) & 0xFF;
    last_raw[ 9] = (ip_addr[ 2] >> 16) & 0xFF;
    last_raw[10] = (ip_addr[ 2] >>  8) & 0xFF;
    last_raw[11] =  ip_addr[ 2] & 0xFF;
    last_raw[12] = (ip_addr[ 3] >> 24) & 0xFF;
    last_raw[13] = (ip_addr[ 3] >> 16) & 0xFF;
    last_raw[14] = (ip_addr[ 3] >>  8) & 0xFF;
    last_raw[15] =  ip_addr[ 3] & 0xFF;
    return EXIT_SUCCESS;
}

static int raw_ip2literal_4(char *out, const size_t max_out, const uint8_t *raw, const size_t raw_size) {
    if (max_out < 12) {
        return ERANGE;
    }

    snprintf(out, max_out, "%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3]);

    return EXIT_SUCCESS;
}

static int raw_ip2literal_6(char *out, const size_t max_out, const uint8_t *raw, const size_t raw_size) {
    size_t o = 0;
    size_t ct[2] = { 0, 0 };
    char *z_p = NULL;
    char *z_p_end = NULL;
    char *p = NULL;
    char *p_end = NULL;
    char *l_p = NULL;
    char temp[1<<10] = "";
    size_t t;
    size_t t_len = snprintf(out, max_out, "%x%.2x:%x%.2x:%x%.2x:%x%.2x:"
                                          "%x%.2x:%x%.2x:%x%.2x:%x%.2x", raw[ 0], raw[ 1], raw[ 2], raw[ 3],
                                                                         raw[ 4], raw[ 5], raw[ 6], raw[ 7],
                                                                         raw[ 8], raw[ 9], raw[10], raw[11],
                                                                         raw[12], raw[13], raw[14], raw[15]);

    p = strstr(out, "000:");
    p_end = out + t_len;
    while (p != NULL) {
        memcpy(p, p + 3, p_end - p);
        p = strstr(out, "000:");
        p_end -= 3;
    }

    p = strstr(out, ":0");
    while (p != NULL) {
        memcpy(p + 1, p + 2, p_end - p);
        p = strstr(out, ":0");
        p_end -= 1;
    }

    p = strstr(out, "::");
    while (p != NULL) {
        l_p = p;
        while (p != p_end && *p == ':') {
            ct[0] += (*p == ':');
            p++;
        }
        if (ct[0] > ct[1]) {
            z_p = l_p;
            z_p_end = p;
            ct[1] = ct[0];
            ct[0] = 0;
        }
        if (p < p_end) {
            p = strstr(p, "::");
            l_p = p;
        } else {
            p = NULL;
        }
    }

    if (z_p != NULL) {
        memcpy(z_p + 2, z_p_end, strlen(z_p_end) + 1);
        p = z_p + 3;
    } else {
        p = out;
    }

    o = 0;
    t_len = strlen(out);
    t = 0;
    memset(temp, 0, sizeof(temp));
    while (o < t_len) {
        if (out[o] == ':' && out[o + 1] == ':' && &out[o] != z_p) {
            memcpy(&temp[t], ":0", 2);
            t += 2;
            o += 1;
        } else {
            temp[t++] = out[o++];
        }
    }
    snprintf(out, max_out, "%s", temp);

    return EXIT_SUCCESS;
}

static int get_last_net_addr4(uint8_t *last, const char *cidr_addr, const size_t cidr_addr_size,
                          const size_t cidr_net_bitsize) {
    uint8_t addr[4] = { 0 };
    uint32_t temp = 0L;
    if (get_raw_ip4(addr, 4, cidr_addr, cidr_addr_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    temp = (0xFFFFFFFF >> cidr_net_bitsize);
    last[0] = addr[0] | ((temp >> 24) & 0xFF);
    last[1] = addr[1] | ((temp >> 16) & 0xFF);
    last[2] = addr[2] | ((temp >>  8) & 0xFF);
    last[3] = addr[3] | (temp & 0xFF);
    return EXIT_SUCCESS;
}

static int get_last_net_addr6(uint8_t *last, const char *cidr_addr, const size_t cidr_addr_size,
                          const size_t cidr_net_bitsize) {
    uint8_t addr[16] = { 0 };
    uint32_t temp[4] = { 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF };
    if (get_raw_ip6(addr, 16, cidr_addr, cidr_addr_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    shiftr128b(temp, cidr_net_bitsize);
    last[ 0] = addr[ 0] | ((temp[ 0] >> 24) & 0xFF);
    last[ 1] = addr[ 1] | ((temp[ 0] >> 16) & 0xFF);
    last[ 2] = addr[ 2] | ((temp[ 0] >>  8) & 0xFF);
    last[ 3] = addr[ 3] | ( temp[ 0] & 0xFF);
    last[ 4] = addr[ 4] | ((temp[ 1] >> 24) & 0xFF);
    last[ 5] = addr[ 5] | ((temp[ 1] >> 16) & 0xFF);
    last[ 6] = addr[ 6] | ((temp[ 1] >>  8) & 0xFF);
    last[ 7] = addr[ 7] | ( temp[ 1] & 0xFF);
    last[ 8] = addr[ 8] | ((temp[ 2] >> 24) & 0xFF);
    last[ 9] = addr[ 9] | ((temp[ 2] >> 16) & 0xFF);
    last[10] = addr[10] | ((temp[ 2] >> 8) & 0xFF);
    last[11] = addr[11] | ( temp[ 2] & 0xFF);
    last[12] = addr[12] | ((temp[ 3] >> 24) & 0xFF);
    last[13] = addr[13] | ((temp[ 3] >> 16) & 0xFF);
    last[14] = addr[14] | ((temp[ 3] >>  8) & 0xFF);
    last[15] = addr[15] | ( temp[ 3] & 0xFF);
    return EXIT_SUCCESS;
}
