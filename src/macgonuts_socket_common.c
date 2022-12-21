/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_socket_common.h>
#include <string.h>

typedef int (*get_addr_from_iface_func)(char *, const size_t, const char *);

static int get_addr4_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface);

static int get_addr6_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface);

int macgonuts_get_addr_from_iface_unix(char *addr_buf, const size_t max_addr_buf_size,
                                       const int addr_version, const char *iface) {
    get_addr_from_iface_func get_addr_from_iface = NULL;
    if (addr_buf == NULL
        || max_addr_buf_size == 0
        || iface == NULL
        || (addr_version != 4 && addr_version != 6)) {
        return EINVAL;
    }
    get_addr_from_iface = (addr_version == 4) ? get_addr4_from_iface : get_addr6_from_iface;
    return get_addr_from_iface(addr_buf, max_addr_buf_size, iface);
}

int get_addr4_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface) {
    int sockfd = -1;
    struct ifreq req = { 0 };
    struct sockaddr *addr = NULL;
    int err = EFAULT;

    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        err = errno;
        goto get_addr4_from_iface_epilogue;
    }

    strncpy(req.ifr_name, iface, sizeof(req.ifr_name) - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &req) == -1) {
        err = errno;
        goto get_addr4_from_iface_epilogue;
    }

    addr = &req.ifr_addr;
    err = (inet_ntop(AF_INET,
                &(((struct sockaddr_in *)addr)->sin_addr),
                addr_buf, max_addr_buf_size - 1) != NULL) ? EXIT_SUCCESS
                                                          : errno;
get_addr4_from_iface_epilogue:

    if (sockfd != -1) {
        close(sockfd);
    }

    return err;
}

int get_addr6_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface) {
    struct ifaddrs *ifa = NULL, *ifp = NULL;
    int err = EFAULT;
    struct sockaddr_in6 *addr = NULL;

    if (max_addr_buf_size < INET6_ADDRSTRLEN) {
        return ERANGE;
    }

    if (getifaddrs(&ifa) == -1) {
        err = errno;
        goto get_addr6_from_iface_epilogue;
    }

    for (ifp = ifa; ifp != NULL; ifp = ifp->ifa_next) {
        if (strcmp(ifp->ifa_name, iface) == 0
            && ifp->ifa_addr != NULL
            && ifp->ifa_addr->sa_family == AF_INET6) {
            addr = (struct sockaddr_in6 *)ifp->ifa_addr;
            err = (inet_ntop(AF_INET6,
                    &(((struct sockaddr_in6 *)ifp->ifa_addr)->sin6_addr),
                    addr_buf, max_addr_buf_size - 1) != NULL) ? EXIT_SUCCESS
                                                              : errno;
            break;
        }
    }

get_addr6_from_iface_epilogue:

    if (ifa != NULL) {
        freeifaddrs(ifa);
    }

    return err;
}

int macgonuts_get_gateway_addr_info(char *iface_buf, const size_t iface_buf_size,
                                    uint8_t *raw, size_t *raw_size) {
    char buf[64<<10] = "";
    uint8_t *rp = NULL;
    ssize_t buf_size;
    char *bp = NULL;
    char *bp_end = NULL;
    char *l_bp = NULL;
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
            memset(iface_buf, 0, sizeof(iface_buf));
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
#define get_nbvalue(n) ( isdigit(n) ? ((n) - 48) : (toupper(n) - 55) )
        *rp = get_nbvalue(bp_end[-1]) << 4 | get_nbvalue(bp_end[0]);
#undef get_nbvalue
        bp_end -= 2;
        rp++;
    }
    *raw_size = (rp - raw);
    return EXIT_SUCCESS;
}
