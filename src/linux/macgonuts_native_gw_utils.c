/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>

#define get_nbvalue(n) ( isdigit(n) ? ((n) - 48) : (toupper(n) - 55) )

int get_gw_addr6_info(uint8_t *raw, size_t *raw_size, const char *iface) {
    int fd = -1;
    char buf[64<<10] = "";
    ssize_t buf_size = 0;
    char *bp = NULL;
    uint8_t *rp = NULL;
    uint8_t *rp_end = NULL;

    *raw_size = 0;

    if (strcmp(iface, "lo") == 0) {
        return EXIT_FAILURE;
    }

    fd = open("/proc/net/ipv6_route", O_RDONLY);
    if (fd == -1) {
        return EXIT_FAILURE;
    }

    buf_size = read(fd, buf, sizeof(buf));
    close(fd);

    if (buf_size == -1) {
        return EXIT_FAILURE;
    }

    bp = strstr(buf, iface);
    if (bp == NULL) {
        return EXIT_FAILURE;
    }

    while (bp != &buf[0] && bp[-1] != '\n') {
        bp--;
    }

    rp = raw;
    rp_end = rp + 16;
    while (rp != rp_end) {
        *rp = get_nbvalue(bp[0]) << 4 | get_nbvalue(bp[1]);
        bp += 2;
        rp++;
    }

    *raw_size = 16;

    return EXIT_SUCCESS;
}

int get_gw_addr4_info(uint8_t *raw, size_t *raw_size, const char *iface) {
    int fd = -1;
    char buf[64<<10] = "";
    ssize_t buf_size = 0;
    char *bp = NULL;
    char *bp_end = NULL;
    uint8_t *rp = NULL;
    uint8_t *rp_end = NULL;

    *raw_size = 0;

    fd = open("/proc/net/route", O_RDONLY);
    if (fd == -1) {
        return EXIT_FAILURE;
    }

    buf_size = read(fd, buf, sizeof(buf));
    close(fd);

    if (buf_size == -1) {
        return EXIT_FAILURE;
    }

    bp = strstr(buf, iface);
    if (bp == NULL) {
        return EXIT_FAILURE;
    }

    bp_end = &buf[0] + buf_size;
    buf_size = 0;
    while (buf_size < 3 && bp != bp_end) {
        buf_size += (*bp == '\t');
        bp++;
    }

    if (buf_size != 3 || bp == bp_end) {
        return EXIT_FAILURE;
    }

    rp = &raw[0];
    rp_end = rp + 5;
    bp -= 2;
    while (rp != rp_end) {
        *rp = get_nbvalue(bp[-1]) << 4 | get_nbvalue(bp[0]);
        bp -= 2;
        rp++;
    }

    *raw_size = 4;

    return EXIT_SUCCESS;
}

int macgonuts_get_gateway_addr_info(char *iface_buf, const size_t iface_buf_size,
                                    uint8_t *raw, size_t *raw_size) {
    char buf[64<<10] = "";
    uint8_t *rp = NULL;
    ssize_t buf_size;
    char *bp = NULL;
    char *bp_end = NULL;
    char *l_bp = NULL;
    if (iface_buf == NULL || iface_buf_size == 0 || raw == NULL || raw_size == NULL) {
        return EINVAL;
    }
    int fd = open("/proc/net/route", O_RDONLY);
    if (fd == -1) {
        return EXIT_FAILURE;
    }
    buf_size = read(fd, buf, sizeof(buf));
    close(fd);
    bp_end = buf + buf_size;
    bp = strstr(buf, "\n");
    if (bp == NULL) {
        return EXIT_FAILURE;
    }
    while (bp != bp_end && (*bp == '\n' || *bp == '\t' || *bp == '\r')) {
        bp++;
    }
    l_bp = bp;
    buf_size = 0;
    // INFO(Rafael): Finding out the default gateway.
    while (buf_size < 2 && bp != bp_end) {
        buf_size += (*bp == '\t');
        if (buf_size == 1) {
            memset(iface_buf, 0, iface_buf_size);
            memcpy(iface_buf, l_bp, (bp - l_bp) % sizeof(iface_buf));
        }
        bp++;
    }
    if (buf_size != 2) {
        return EXIT_FAILURE;
    }
    bp_end = strstr(bp, "\t");
    if (bp_end == NULL) {
        return EXIT_FAILURE;
    }
    bp_end -= 1;
    bp -= 1;
    rp = raw;
    while (bp_end > bp) {
        *rp = get_nbvalue(bp_end[-1]) << 4 | get_nbvalue(bp_end[0]);
        bp_end -= 2;
        rp++;
    }
    *raw_size = (rp - raw);
    return EXIT_SUCCESS;
}

#undef get_nbvalue
