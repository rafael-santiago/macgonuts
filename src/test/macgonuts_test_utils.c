/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_test_utils.h"
#include <macgonuts_ipconv.h>

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
#define get_nbv(n) ( isdigit((n)) ? ((n) - 48) : (toupper((n)) - 55) )
        iface_mac[m++] = (uint8_t)get_nbv(bp[0]) << 4 | (uint8_t)get_nbv(bp[1]);
        bp += 3;
#undef get_nbv
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
