/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>
#include <macgonuts_ipconv.h>

int get_gw_addr4_info(uint8_t *raw, size_t *raw_size, const char *iface) {
    int err = EXIT_FAILURE;
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
        goto get_gw_addr4_info_epilogue;
    }

    *raw_size = 0;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &buf_size, NULL, 0) == -1) {
        goto get_gw_addr4_info_epilogue;
    }

    buf = (char *)malloc(buf_size);

    if (sysctl(mib, 6, buf, &buf_size, NULL, 0) == -1) {
        goto get_gw_addr4_info_epilogue;
    }

    bp = buf;
    bp_end = bp + buf_size;

    while (bp < bp_end && err != EXIT_SUCCESS) {
        rtp = (struct rt_msghdr *)bp;
        if (rtp->rtm_index == if_index) {
            sa = (struct sockaddr *) (rtp + 1);
            sa = (struct sockaddr *)(SA_SIZE(sa) + (char *)sa);
            sk_in = (struct sockaddr_in *)sa;
            memcpy(&raw[0], &sk_in->sin_addr.s_addr, 4);
            *raw_size = 4;
            err = EXIT_SUCCESS;
        }
        bp += rtp->rtm_msglen;
    }

get_gw_addr4_info_epilogue:

    if (buf != NULL) {
        free(buf);
    }

    return err;
}

int get_gw_addr6_info(uint8_t *raw, size_t *raw_size, const char *iface) {
    char cmd[1<<10] = "";
    FILE *proc = NULL;
    char *cp = NULL;
    int err = EXIT_FAILURE;
    uint8_t dummy[16] = { 0 };

    // TODO(Rafael): Improve it on.

    *raw_size = 0;

    snprintf(cmd, sizeof(cmd) - 1, "netstat -6rn | grep %s | grep -v link", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        goto get_gw_addr6_info_epilogue;
    }

    fread(cmd, 1, sizeof(cmd), proc);
    cp = strstr(cmd, " ");
    if (cp != NULL) {
        *cp = 0;
    }
    pclose(proc);
    proc = NULL;

    err = macgonuts_get_raw_ip_addr(raw, 16, cmd, strlen(cmd));

    if (err == EXIT_SUCCESS) {
        *raw_size = 16;
        goto get_gw_addr6_info_epilogue;
    }

    snprintf(cmd, sizeof(cmd) - 1, "netstat -6rn | grep %s", iface);
    proc = popen(cmd, "r");
    if (proc == NULL) {
        goto get_gw_addr6_info_epilogue;
    }

    fread(cmd, 1, sizeof(cmd), proc);
    cp = strstr(cmd, " ");
    if (cp != NULL) {
        *cp = 0;
    }

    err = macgonuts_get_raw_cidr(raw, dummy, cmd, strlen(cmd));

    if (err == EXIT_SUCCESS) {
        *raw_size = 16;
    }

get_gw_addr6_info_epilogue:

    if (proc != NULL) {
        pclose(proc);
    }

    return err;
}

int macgonuts_get_gateway_addr_info(char *iface_buf, const size_t iface_buf_size,
                                    uint8_t *raw, size_t *raw_size) {
    int err = EXIT_FAILURE;
    int mib[6];
    size_t buf_size = 0;
    char *buf = NULL;
    struct rt_msghdr *rtp = NULL;
    struct sockaddr *sa = NULL;
    struct sockaddr_in *sk_in = NULL;

    if (iface_buf == NULL
        || iface_buf_size == 0
        || raw == 0
        || raw_size == NULL) {
        return EINVAL;
    }

    *raw_size = 0;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &buf_size, NULL, 0) == -1) {
        goto macgonuts_get_gateway_addr_info_epilogue;
    }

    buf = (char *)malloc(buf_size);

    if (sysctl(mib, 6, buf, &buf_size, NULL, 0) == -1) {
        goto macgonuts_get_gateway_addr_info_epilogue;
    }

    rtp = (struct rt_msghdr *)buf;
    sa = (struct sockaddr *) (rtp + 1);
    sa = (struct sockaddr *)(SA_SIZE(sa) + (char *)sa);
    sk_in = (struct sockaddr_in *)sa;
    memcpy(&raw[0], &sk_in->sin_addr.s_addr, 4);
    *raw_size = 4;

    if (iface_buf_size < IFNAMSIZ
        || if_indextoname(rtp->rtm_index, iface_buf) == NULL) {
        *raw_size = 0;
        memset(&raw[0], 0, 4);
        goto macgonuts_get_gateway_addr_info_epilogue;
    }

    err = EXIT_SUCCESS;

macgonuts_get_gateway_addr_info_epilogue:

    if (buf != NULL) {
        free(buf);
    }

    return err;
}
