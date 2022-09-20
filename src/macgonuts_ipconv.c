#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static int chk_ipv4_addr(const char *ip, const size_t ip_size);

static int chk_ipv6_addr(const char *ip, const size_t ip_size);

static int chk_ipvn_range(const size_t n, const char *ip, const size_t ip_size);

static int chk_ipv4_range(const char *ip, const size_t ip_size);

static int chk_ipv6_range(const char *ip, const size_t ip_size);

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
    int is_valid = 0;
    switch (macgonuts_get_ip_version(ip, ip_size)) {
        case 4:
            is_valid = chk_ipv4_addr(ip, ip_size);
            break;

        case 6:
            is_valid = chk_ipv6_addr(ip, ip_size);
            break;

        default:
            break;
    }
    return is_valid;
}

int macgonuts_check_ip_range(const char *ip, const size_t ip_size) {
    int is_valid = 0;
    switch(macgonuts_get_ip_version(ip, ip_size)) {
        case 4:
            is_valid = chk_ipv4_range(ip, ip_size);
            break;

        case 6:
            is_valid = chk_ipv6_range(ip, ip_size);
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
            dots_nr++;
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
    if (p == NULL) {
        return 0;
    }
    while (p < p_end) {
        if (*p == ':' || (p + 1) == p_end) {
            p += ((p + 1) == p_end);
            if ((p - lp) > sizeof(word)) {
                return 0;
            }
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
    return 1;
}

static int chk_ipvn_range(const size_t n, const char *ip, const size_t ip_size) {
    char addr[100] = { 0 };
    char *ap = NULL;
    int cidr_nr = 0;
    int (*chk_ipvn_addr)(const char *, const size_t) = (n == 4) ? chk_ipv4_addr : chk_ipv6_addr;
    if (ip == NULL) {
        return 0;
    }
    memcpy(addr, ip, ip_size % sizeof(addr) - 1);
    ap = strstr(addr, "/");
    if (ap == NULL) {
        return 0;
    }
    *ap = 0;
    if (chk_ipvn_addr(addr, strlen(addr)) == 0) {
        return 0;
    }
    ap += 2;
    if (!is_int(ap, strlen(ap))) {
        return 0;
    }
    cidr_nr = atoi(ap);
    return (n == 4) ? (cidr_nr > 0 && cidr_nr < 32) : (cidr_nr > 0 && cidr_nr < 128);
}

static int chk_ipv4_range(const char *ip, const size_t ip_size) {
    return chk_ipvn_range(4, ip, ip_size);
}

static int chk_ipv6_range(const char *ip, const size_t ip_size) {
    return chk_ipvn_range(6, ip, ip_size);
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
