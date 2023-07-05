/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_socket_common.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_socket.h>
#include <macgonuts_ipconv.h>
#include <string.h>

typedef int (*get_addr_from_iface_func)(char *, const size_t, const char *);

static int get_addr4_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface);

static int get_addr6_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface);

static int get_netmask4(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw);

static int get_netmask6(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw);

extern int get_gw_addr4_info(uint8_t *raw, size_t *raw_size, const char *iface);

extern int get_gw_addr6_info(uint8_t *raw, size_t *raw_size, const char *iface);

static int get_maxaddr4(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw);

static int get_maxaddr6(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw);

int macgonuts_get_gateway_addr_info_from_iface(uint8_t *raw, size_t *raw_size, const int ip_version, const char *iface) {
    int (*get_gw_addr_info)(uint8_t *, size_t *, const char *) = NULL;
    if (raw == NULL
        || raw_size == NULL
        || (ip_version != 4 && ip_version != 6)
        || iface == NULL) {
        return EINVAL;
    }
    get_gw_addr_info = (ip_version == 4) ? get_gw_addr4_info : get_gw_addr6_info;
    return get_gw_addr_info(raw, raw_size, iface);
}

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

int macgonuts_get_netmask_from_iface(const char *iface_buf, const size_t iface_buf_size,
                                     uint8_t *raw, const int ip_version) {
    int (*get_netmask)(const char *, const size_t, uint8_t *) = NULL;

    if (iface_buf == NULL
        || iface_buf_size == 0
        || raw == NULL
        || (ip_version != 4 && ip_version != 6)) {
        return EINVAL;
    }

    switch (ip_version) {
        case 4:
            get_netmask = get_netmask4;
            break;

        case 6:
            get_netmask = get_netmask6;
            break;

        default:
            // INFO(Rafael): It should never happen in normal conditions.
            return EXIT_FAILURE;
    }

    assert(get_netmask != NULL);

    return get_netmask(iface_buf, iface_buf_size, raw);
}

int macgonuts_get_maxaddr_from_iface(const char *iface_buf,
                                     const size_t iface_buf_size,
                                     uint8_t *raw, const int ip_version) {
    int (*get_maxaddr)(const char *, const size_t, uint8_t *) = NULL;

    if (iface_buf == NULL
        || iface_buf_size == 0
        || raw == NULL
        || (ip_version != 4 && ip_version != 6)) {
        return EINVAL;
    }

    switch (ip_version) {
        case 4:
            get_maxaddr = get_maxaddr4;
            break;

        case 6:
            get_maxaddr = get_maxaddr6;
            break;

        default:
            // INFO(Rafael): It should never happen in normal conditions.
            return EXIT_FAILURE;
    }

    assert(get_maxaddr != NULL);

    return get_maxaddr(iface_buf, iface_buf_size, raw);
}

int macgonuts_get_gateway_hw_addr(uint8_t *hw_addr, const size_t hw_addr_size) {
    uint8_t gw_addr[16] = { 0 };
    size_t gw_addr_size = 0;
    char gw_proto_addr[100] = "";
    char iface[256] = "";
    macgonuts_socket_t wire = -1;
    int err = EFAULT;

    if (hw_addr == NULL || hw_addr_size == 0) {
        return EINVAL;
    }

    if (macgonuts_get_gateway_addr_info(iface, sizeof(iface), gw_addr, &gw_addr_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (macgonuts_raw_ip2literal(gw_proto_addr,
                                 sizeof(gw_proto_addr) - 1,
                                 gw_addr, gw_addr_size) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    wire = macgonuts_create_socket(iface, 1);
    if (wire == -1) {
        return EXIT_FAILURE;
    }
    err = macgonuts_get_ethaddr(hw_addr, hw_addr_size,
                                gw_proto_addr, strlen(gw_proto_addr),
                                wire, iface);
    macgonuts_release_socket(wire);
    return err;
}

static int get_addr4_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface) {
    int sockfd = -1;
    struct ifreq req;
    struct sockaddr *addr = NULL;
    int err = EFAULT;

    memset(&req, 0, sizeof(req));

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

static int get_addr6_from_iface(char *addr_buf, const size_t max_addr_buf_size, const char *iface) {
    struct ifaddrs *ifa = NULL, *ifp = NULL;
    int err = EFAULT;

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

static int get_maxaddr4(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw) {
    struct ifreq ifr;
    int err = EFAULT;
    int sockfd = -1;
    uint8_t netmask[4] = { 0 };

    memset(&ifr, 0, sizeof(ifr));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        err = errno;
        goto get_maxaddr4_epilogue;
    }

    memcpy(ifr.ifr_name, iface_buf, iface_buf_size);
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
        err = errno;
        goto get_maxaddr4_epilogue;
    }

    memcpy(&netmask[0], &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr, 4);
    netmask[0] = ~netmask[0];
    netmask[1] = ~netmask[1];
    netmask[2] = ~netmask[2];
    netmask[3] = ~netmask[3];

    if(ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        err = errno;
        goto get_maxaddr4_epilogue;
    }

    memcpy(&raw[0], &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr, 4);
    raw[0] |= netmask[0];
    raw[1] |= netmask[1];
    raw[2] |= netmask[2];
    raw[3] |= netmask[3];

    err = EXIT_SUCCESS;

get_maxaddr4_epilogue:

    if (sockfd > -1) {
        close(sockfd);
    }

    return err;
}

static int get_maxaddr6(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw) {
    struct ifaddrs *ifaddrs = NULL;
    struct ifaddrs *ifp = NULL;
    int err = EXIT_FAILURE;
    uint8_t netmask[16] = { 0 };
    uint8_t in_addr[16] = { 0 };
    char cidr6[1<<10] = "";
    ssize_t cidr6_size = 0;
    size_t prefixlen = 0;
    size_t n;

    if (getifaddrs(&ifaddrs)) {
        err = errno;
        goto get_maxaddr6_epilogue;
    }

    err = ENOENT;
    for (ifp = ifaddrs; ifp != NULL && err == ENOENT; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr->sa_family == AF_INET6
            && strcmp(ifp->ifa_name, iface_buf) == 0) {
            memcpy(&in_addr[0], &(((struct sockaddr_in6 *)(ifp->ifa_addr)))->sin6_addr.s6_addr, 16);
            if (in_addr[0] == 0xFE && in_addr[1] == 0x80) {
                continue;
            }
            memcpy(&netmask[0], &(((struct sockaddr_in6 *)(ifp->ifa_netmask)))->sin6_addr.s6_addr, 16);
            for (n = 0; n < 16; n++) {
                prefixlen += ((netmask[n] >> 7) & 1) +
                             ((netmask[n] >> 6) & 1) +
                             ((netmask[n] >> 5) & 1) +
                             ((netmask[n] >> 4) & 1) +
                             ((netmask[n] >> 3) & 1) +
                             ((netmask[n] >> 2) & 1) +
                             ((netmask[n] >> 1) & 1) +
                             (netmask[n] & 1);
            }
            cidr6_size = snprintf(cidr6, sizeof(cidr6),
                                  "%.2X%.2X:%.2X%.2X:%.2X%.2X:%2X%.2X:%.2X%.2X:%.2X%.2X:%.2X%.2X:%.2X%.2X/%zu",
                                  in_addr[ 0], in_addr[ 1], in_addr[ 2], in_addr[ 3],
                                  in_addr[ 4], in_addr[ 5], in_addr[ 6], in_addr[ 7],
                                  in_addr[ 8], in_addr[ 9], in_addr[10], in_addr[11],
                                  in_addr[12], in_addr[13], in_addr[14], in_addr[15], prefixlen);
            if (cidr6_size <= 0) {
                err = EFAULT;
                goto get_maxaddr6_epilogue;
            }
            err = macgonuts_get_last_net_addr(raw, cidr6, cidr6_size);
        }
    }

get_maxaddr6_epilogue:

    if (ifaddrs != NULL) {
        freeifaddrs(ifaddrs);
    }

    return err;
}

static int get_netmask4(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw) {
    struct ifreq ifr;
    int err = EFAULT;
    int sockfd = -1;

    memset(&ifr, 0, sizeof(ifr));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        err = errno;
        goto get_netmask4_epilogue;
    }

    memcpy(ifr.ifr_name, iface_buf, iface_buf_size);
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
        err = errno;
        goto get_netmask4_epilogue;
    }

    memcpy(&raw[0], &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr, 4);

    err = EXIT_SUCCESS;

get_netmask4_epilogue:

    if (sockfd > -1) {
        close(sockfd);
    }

    return err;
}

static int get_netmask6(const char *iface_buf, const size_t iface_buf_size, uint8_t *raw) {
    struct ifaddrs *ifaddrs = NULL;
    struct ifaddrs *ifp = NULL;
    int err = EXIT_FAILURE;

    if (getifaddrs(&ifaddrs)) {
        err = errno;
        goto get_netmask6_epilogue;
    }

    err = ENOENT;
    for (ifp = ifaddrs; ifp != NULL && err == ENOENT; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr->sa_family == AF_INET6
            && strcmp(ifp->ifa_name, iface_buf) == 0) {
            memcpy(&raw[0], &(((struct sockaddr_in6 *)(ifp->ifa_netmask)))->sin6_addr.s6_addr, 16);
            err = EXIT_SUCCESS;
        }
    }

get_netmask6_epilogue:

    if (ifaddrs != NULL) {
        freeifaddrs(ifaddrs);
    }

    return err;
}

