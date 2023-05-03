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
    proc = popen("ifconfig | grep \"inet.*\" | sed s/.*inet// | sed s/.netmask.*// | head -1", "r");
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
    proc = popen("route | grep \"^default\"", "r");
    if (proc == NULL) {
        return;
    }
    buf_size = fread(&buf[0], 1, sizeof(buf), proc);
    pclose(proc);
    bp = &buf[0] + 7;
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
    memcpy(&s_addr[0], lp, bp - lp);
    done = (macgonuts_get_raw_ip_addr(gw_addr, sizeof(gw_addr), s_addr, bp - lp) == EXIT_SUCCESS);
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
    proc = popen("route | grep \"^default\"", "r");
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

/*
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
*/

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

int get_maxaddr6_from_iface(uint8_t *addr, const char *iface) {
    FILE *proc = NULL;
    char cmd[1<<10] = "";
    char buf[1<<10] = "";
    size_t buf_size;
    char *p[2] = { NULL, NULL };
    snprintf(cmd, sizeof(cmd) - 1, "ifconfig %s | grep scopeid.*global | sed s/.*inet6// | "
                                   "sed s/prefixlen.// | sed s/scopeid.*//", iface);
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

#undef get_nbv
