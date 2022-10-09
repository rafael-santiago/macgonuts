/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

static int get_iface_index(const char *iface);

macgonuts_socket_t macgonuts_create_socket(const char *iface) {
    struct timeval tv = { 0 };
    int yes = 1;
    macgonuts_socket_t sockfd = -1;
    struct sockaddr_ll sll = { 0 };
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket()");
        fprintf(stderr, "error: unable to create raw socket.\n");
        return -1;
    }
    tv.tv_sec = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = get_iface_index(iface);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        perror("bind()");
        fprintf(stderr, "error: cannot bind raw socket.\n");
        macgonuts_release_socket(sockfd);
        return -1;
    }
    return sockfd;
}

void macgonuts_release_socket(const macgonuts_socket_t sockfd) {
    close(sockfd);
}

int macgonuts_get_mac_from_iface(char *mac_buf, const size_t max_mac_buf_size, const char *iface) {
    int sockfd = -1;
    struct ifconf ifc = { 0 };
    struct ifreq ifr = { 0 }, *ifp = NULL, *ifp_end = NULL;
    char buf[32] = "";
    int err = EFAULT;

    if (mac_buf == NULL || max_mac_buf_size == 0 || iface == NULL) {
        return EINVAL;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = &buf[0];
    sockfd = socket(PF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        err = errno;
        goto macgonuts_get_mac_from_iface_epilogue;
    }

    if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
        err = errno;
        goto macgonuts_get_mac_from_iface_epilogue;
    }

    ifp = ifc.ifc_req;
    ifp_end = ifp + ifc.ifc_len / sizeof(ifc);

    while (ifp != ifp_end) {
        if (strcmp(ifp->ifr_name, iface) == 0) {
            strncpy(ifr.ifr_name, ifp->ifr_name, sizeof(ifr.ifr_name) - 1);
            if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1
                || (ifr.ifr_flags & IFF_LOOPBACK)
                || ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
                err = errno;
                goto macgonuts_get_mac_from_iface_epilogue;
            }
            snprintf(mac_buf,
                     max_mac_buf_size - 1, "%.2x:%.2x:%.2x"
                                           "%.2x:%.2x:%.2x", ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1],
                                                             ifr.ifr_hwaddr.sa_data[2], ifr.ifr_hwaddr.sa_data[3],
                                                             ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
            err = EXIT_SUCCESS;
            break;
        }
        ifp++;
    }

macgonuts_get_mac_from_iface_epilogue:

    if (sockfd != -1) {
        close(sockfd);
    }

    return err;
}

ssize_t macgonuts_sendpkt(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size) {
    return sendto(sockfd, buf, buf_size, 0, NULL, 0);
}

ssize_t macgonuts_recvpkt(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size) {
    return recvfrom(sockfd, buf, buf_size, 0, NULL, 0);
}

static int get_iface_index(const char *iface) {
    struct ifreq ifr = { 0 };
    macgonuts_socket_t sockfd = -1;
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        fprintf(stderr, "error: unable to create temporary socket.\n");
        return -1;
    }
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
        ifr.ifr_ifindex = -1;
    }
    close(sockfd);
    return ifr.ifr_ifindex;
}
