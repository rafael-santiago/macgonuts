/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>

static int g_IPv = 4;

static char g_IP4Addr[1<<10];

static char g_IP6Addr[1<<10];

static unsigned char g_RecvBuf[64<<10];

static ssize_t g_RecvBufSize = -1;

void mock_set_expected_ip_version(const int version) {
    g_IPv = version;
}

void mock_set_expected_ip4_addr(const char *addr) {
    snprintf(g_IP4Addr, sizeof(g_IP4Addr) - 1, "%s", addr);
}

void mock_set_expected_ip6_addr(const char *addr) {
    snprintf(g_IP6Addr, sizeof(g_IP6Addr) - 1, "%s", addr);
}

void mock_set_recv_buf(const unsigned char *buf, const size_t buf_size) {
    g_RecvBufSize = buf_size % (sizeof(g_RecvBuf) / sizeof(g_RecvBuf[0]));
    memcpy(g_RecvBuf, buf, g_RecvBufSize);
}

ssize_t macgonuts_sendpkt(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size) {
    return buf_size; // INFO(Rafael): Always ok.
}

ssize_t macgonuts_recvpkt(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size) {
    ssize_t bytes_nr = -1;
    switch (g_IPv) {
        case 4:
        case 6:
            bytes_nr = g_RecvBufSize;
            memcpy(buf, g_RecvBuf, bytes_nr);
            break;

        default:
            fprintf(stderr, "test setup error: you must set g_IPv to 4 or 6.\n");
            break;
    }
    return bytes_nr;
}

int macgonuts_get_addr_from_iface(char *addr_buf, const size_t max_addr_buf_size,
                                  const int addr_version, const char *iface) {
    int err = ENOTSUP;
    switch (g_IPv) {
        case 4:
            snprintf(addr_buf, max_addr_buf_size, "%s", g_IP4Addr);
            err = EXIT_SUCCESS;
            break;

        case 6:
            snprintf(addr_buf, max_addr_buf_size, "%s", g_IP6Addr);
            err = EXIT_SUCCESS;
            break;

        default:
            fprintf(stderr, "test setup error: you must set g_IPv to 4 or 6.\n");
            break;
    }
    return err;
}
