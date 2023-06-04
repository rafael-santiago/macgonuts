/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_test_utils.h"
#include <macgonuts_ipconv.h>

#define get_nbv(n) ( isdigit((n)) ? ((n) - 48) : (toupper((n)) - 55) )

const char *get_default_iface_name(void) {
    FILE *proc = NULL;
    static char iface_name[1<<10] = "";
    char *p = NULL;
    if (iface_name[0] != 0) {
        return &iface_name[0];
    }
    proc = popen("ifconfig | sed s/:.*// | head -1", "r");
    if (proc == NULL) {
        return NULL;
    }
    fread(&iface_name[0], 1, sizeof(iface_name), proc);
    p = strstr(iface_name, "\n");
    if (p != NULL) {
        *p = 0;
    }
    pclose(proc);
    return &iface_name[0];
}

void get_default_iface_mac(uint8_t *mac) {
    FILE *proc = NULL;
    static uint8_t iface_mac[6] = { 0 };
    static int done = 0;
    char buf[1<<10] = "";
    size_t buf_size;
    size_t m = 0;
    char *bp = NULL;
    char *bp_end = NULL;
    if (done) {
        memcpy(mac, &iface_mac[0], sizeof(iface_mac));
        return;
    }
    proc = popen("ifconfig | grep \"ether.*\" | sed s/.*ether.// | sed s/.tx.*// | head -1", "r");
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    bp = &buf[0];
    bp_end = bp + buf_size;
    while (bp < bp_end && m < sizeof(iface_mac)) {
        iface_mac[m++] = (uint8_t)get_nbv(bp[0]) << 4 | (uint8_t)get_nbv(bp[1]);
        bp += 3;
    }
    memcpy(mac, &iface_mac[0], sizeof(iface_mac));
    done = 1;
}

void get_default_iface_addr(char *addr) {
    FILE *proc = NULL;
    static char iface_addr[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size = 0;
    char *p = NULL;
    if (iface_addr[0] != 0) {
        memcpy(addr, &iface_addr[0], strlen(iface_addr));
        return;
    }
    proc = popen("ifconfig | grep \"inet .*\" | sed s/.*inet// | sed s/.netmask.*// | head -1", "r");
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    p = strstr(buf, "\n");
    if (p != NULL) {
        *p = 0;
    }
    p = &buf[0];
    while (isblank(*p)) {
        p++;
    }
    memcpy(&iface_addr[0], p, buf_size - (p - &buf[0]));
    p = strstr(iface_addr, " ");
    if (p != NULL) {
        *p = 0;
    }
    memcpy(addr, &iface_addr[0], strlen(iface_addr));
}

void get_gateway_addr(uint8_t *addr) {
    FILE *proc = NULL;
    static uint8_t gw_addr[16] = { 0 };
    static int done = 0;
    char buf[1<<10] = "";
    char *bp = NULL;
    char *bp_end = NULL;
    char *lp = NULL;
    size_t buf_size;
    char s_addr[1<<10] = "";
    if (done) {
        memcpy(addr, &gw_addr[0], sizeof(gw_addr));
        return;
    }
#if defined(__linux__)
    proc = popen("route | grep \"^default\"", "r");
#elif defined(__FreeBSD__)
    proc = popen("route -4 get default | grep \"gateway\" | sed 's/.*gateway://'", "r");
#else
# error Some code wanted.
#endif // defined(__linux__)
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    bp = &buf[0];
#if defined(__linux__)
    bp += 7;
#endif // defined(__linux__)
    bp_end = bp + buf_size;
    while (bp != bp_end && isblank(*bp)) {
        bp++;
    }
    if (bp == bp_end) {
        return;
    }
    lp = bp;
    while (bp != bp_end && !isblank(*bp)) {
        bp++;
    }
    memcpy(&s_addr[0], lp, bp - lp - (bp[-1] == '\n'));
    done = (macgonuts_get_raw_ip_addr(gw_addr, sizeof(gw_addr), s_addr, bp - lp - (bp[-1] == '\n')) == EXIT_SUCCESS);
    if (done) {
        memcpy(addr, &gw_addr[0], sizeof(gw_addr));
    }
}

void get_gateway_iface(char *iface) {
    FILE *proc = NULL;
    static char gw_iface[1<<10] = "";
    char buf[1<<10] = "";
    char *bp = NULL;
    char *bp_end = NULL;
    size_t buf_size;
    if (gw_iface[0] != 0) {
        memcpy(iface, gw_iface, strlen(gw_iface));
        return;
    }
#if defined(__linux__)
    proc = popen("route | grep \"^default\"", "r");
#elif defined(__FreeBSD__)
    proc = popen("route -4 get default | grep \"interface\" | sed 's/.*interface://'", "r");
#else
# error Some code wanted.
#endif // defined(__linux__)
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    bp = &buf[0];
    bp_end = bp + buf_size;
    bp = bp_end - 1;
    while (bp != &buf[0] && !isblank(*bp)) {
        bp--;
    }
    memcpy(gw_iface, bp + 1, bp_end - bp - 2);
    memcpy(iface, gw_iface, strlen(gw_iface));
}

int get_maxaddr4_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size;
    char *p = NULL;
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep .*broadcast | sed s/.*broadcast//", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return EPIPE;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    if (buf[0] != ' ') {
        return EFAULT;
    }
    p = strstr(buf, "\n");
    if (p == NULL) {
        return EFAULT;
    }
    *p = 0;
    return macgonuts_get_raw_ip_addr(addr, 4, &buf[1], buf_size - 2);
}

#if defined(__linux__)

int get_netmask4_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size;
    char *p = NULL;
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep .*netmask | sed s/.*netmask// | sed s/broadcast.*//", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return EPIPE;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    if (buf[0] != ' ') {
        return EFAULT;
    }
    p = strstr(&buf[1], " ");
    if (p == NULL) {
        return EFAULT;
    }
    *p = 0;
    return macgonuts_get_raw_ip_addr(addr, 4, &buf[1], strlen(&buf[1]));
}

#elif defined(__FreeBSD__)

int get_netmask4_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    char *bp = NULL;
    size_t buf_size;
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep .netmask | sed 's/.*netmask //' | sed 's/ broadcast.*//'", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return EPIPE;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    bp = &buf[0] + 2;
    addr[0] = (uint8_t)get_nbv(bp[0]) << 4 | (uint8_t)get_nbv(bp[1]);
    bp += 2;
    addr[1] = (uint8_t)get_nbv(bp[0]) << 4 | (uint8_t)get_nbv(bp[1]);
    bp += 2;
    addr[2] = (uint8_t)get_nbv(bp[0]) << 4 | (uint8_t)get_nbv(bp[1]);
    bp += 2;
    addr[3] = (uint8_t)get_nbv(bp[0]) << 4 | (uint8_t)get_nbv(bp[1]);
    return EXIT_SUCCESS;
}

#else
# error Some code wanted.
#endif // defined(__linux__)

static void shiftl128b(uint32_t *value, const size_t n) {
    unsigned char b = 0;
    size_t c;
    for (c = 0; c < n; c++) {
        b = (value[1] >> 31) & 1;
        value[0] = (value[0] << 1) | (uint32_t)b;
        b = (value[2] >> 31) & 1;
        value[1] = (value[1] << 1) | (uint32_t)b;
        b = (value[3] >> 31) & 1;
        value[2] = (value[2] << 1) | (uint32_t)b;
        value[3] = (value[3] << 1);
    }
}

#if defined(__linux__)

int get_netmask6_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size;
    char *p = NULL;
    uint32_t mask[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep .*prefixlen.*scopeid.*global | sed s/.*prefixlen// | sed s/scopeid.*//", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return EPIPE;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    if (buf[0] != ' ') {
        return EFAULT;
    }
    p = strstr(&buf[1], " ");
    if (p == NULL) {
        return EFAULT;
    }
    *p = 0;
    shiftl128b(mask, atoi(&buf[1]));
    memcpy(addr, &mask[0], sizeof(mask));
    return EXIT_SUCCESS;
}

#elif defined(__FreeBSD__)

int get_netmask6_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size;
    uint32_t mask[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep inet6 | grep -v fe80 | sed 's/.*prefixlen //'", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return EPIPE;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    shiftl128b(mask, atoi(buf));
    memcpy(addr, &mask[0], sizeof(mask));
    return EXIT_SUCCESS;
}

#else
# error Some code wanted.
#endif // defined(__linux__)

int get_maxaddr6_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size;
    char *p[2] = { NULL, NULL };
#if defined(__linux__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep scopeid.*global | sed s/.*inet6// | "
                                   "sed s/prefixlen.// | sed s/scopeid.*//", iface);
#elif defined(__FreeBSD__)
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep inet6 | grep -v fe80 | sed 's/.*inet6//' | "
                                   "sed 's/prefixlen.//'", iface);
#else
# error Some code wanted.
#endif // defined(__linux__)
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return EPIPE;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    if (buf[0] != ' ') {
        return EFAULT;
    }
    p[0] = strstr(&buf[1], " ");
    p[1] = p[0];
    while (*p[1] == ' ') {
        p[1]++;
    }
    *p[0] = '/';
    strcpy(p[0] + 1, p[1]);
    p[0] = &buf[0];
    while (*p[0] == ' ') {
        p[0]++;
    }
    p[1] = strstr(p[0], " ");
    if (p[1] == NULL) {
        return EFAULT;
    }
    *p[1] = 0;

    return macgonuts_get_last_net_addr(addr, p[0], strlen(p[0]));
}

#if defined(__linux__)

void get_gateway_addr4_from_iface(uint8_t *gw_addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    char *bp = NULL;
    char *bp_end = NULL;
    size_t buf_size;
    gw_addr[0] = 0;
    snprintf(cmd, sizeof(cmd) - 1, "cat /proc/net/route | grep %s", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    bp_end = strstr(buf, "\t");
    if (bp_end == NULL) {
        return;
    }
    bp_end = strstr(bp_end + 1, "\t");
    if (bp_end == NULL) {
        return;
    }
    bp = strstr(bp_end + 1, "\t");
    if (bp == NULL) {
        return;
    }
    bp -= 1;
    buf_size = 0;
    while (bp > bp_end) {
        gw_addr[buf_size++] = get_nbv(bp[-1]) << 4 | get_nbv(bp[0]);
        bp -= 2;
    }
}

void get_gateway_addr6_from_iface(uint8_t *gw_addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    char *bp = NULL;
    size_t buf_size;
    gw_addr[0] = 0;
    snprintf(cmd, sizeof(cmd) - 1, "cat /proc/net/ipv6_route | grep %s", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    if (buf[0] == 0) {
        return;
    }
    bp = &buf[0];
    buf_size = 0;
    while (buf_size < 16) {
        gw_addr[buf_size++] = get_nbv(bp[0]) << 4 | get_nbv(bp[1]);
        bp += 2;
    }
}

#elif defined(__FreeBSD__)

void get_gateway_addr4_from_iface(uint8_t *gw_addr, const char *iface) {
    int mib[6];
    size_t buf_size = 0;
    char *buf = NULL;
    char *bp = NULL;
    char *bp_end = NULL;
    struct rt_msghdr *rtp = NULL;
    struct sockaddr *sa = NULL;
    struct sockaddr_in *sk_in = NULL;
    unsigned int if_index = if_nametoindex(iface);

    if (if_index == 0) {
        return;
    }

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &buf_size, NULL, 0) == -1) {
        goto get_gateway_addr4_from_iface_epilogue;
    }

    buf = (char *)malloc(buf_size);

    if (sysctl(mib, 6, buf, &buf_size, NULL, 0) == -1) {
        goto get_gateway_addr4_from_iface_epilogue;
    }

    bp = buf;
    bp_end = bp + buf_size;

    while (bp < bp_end) {
        rtp = (struct rt_msghdr *)bp;
        if (rtp->rtm_index == if_index) {
            sa = (struct sockaddr *) (rtp + 1);
            sa = (struct sockaddr *)(SA_SIZE(sa) + (char *)sa);
            sk_in = (struct sockaddr_in *)sa;
            memcpy(&gw_addr[0], &sk_in->sin_addr.s_addr, 4);
            break;
        }
        bp += rtp->rtm_msglen;
    }

get_gateway_addr4_from_iface_epilogue:

    if (buf != NULL) {
        free(buf);
    }
}

void get_gateway_addr6_from_iface(uint8_t *gw_addr, const char *iface) {
    char cmd[1<<10] = "";
    FILE *proc = NULL;
    char *cp = NULL;
    uint8_t dummy[16] = { 0 };

    snprintf(cmd, sizeof(cmd) - 1, "netstat -6rn | grep %s", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        goto get_gateway_addr6_from_iface_epilogue;
    }

    fread(cmd, 1, sizeof(cmd), proc);
    cp = strstr(cmd, " ");
    if (cp != NULL) {
        *cp = 0;
    }

    macgonuts_get_raw_cidr(gw_addr, dummy, cmd, strlen(cmd));

get_gateway_addr6_from_iface_epilogue:

    if (proc != NULL) {
        pclose(proc);
    }
}

#else
# error Some code wanted.
#endif // defined(__linux__)

#undef get_nbv
