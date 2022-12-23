/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_test_utils.h"

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
}
