/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_socket.h>
#include <macgonuts_status_info.h>
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

static int set_iface_promisc_flag(const int on, const char *iface);

int macgonuts_set_iface_promisc_on(const char *iface) {
    return set_iface_promisc_flag(1, iface);
}

int macgonuts_set_iface_promisc_off(const char *iface) {
    return set_iface_promisc_flag(0, iface);
}

macgonuts_socket_t macgonuts_create_socket(const char *iface, const size_t io_timeo) {
    struct timeval tv = { 0 };
    int yes = 1;
    macgonuts_socket_t sockfd = -1;
    struct sockaddr_ll sll = { 0 };
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        macgonuts_si_error("unable to create raw socket : '%s'\n", strerror(errno));
        return -1;
    }
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = get_iface_index(iface);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        macgonuts_si_error("cannot bind raw socket : '%s'\n", strerror(errno));
        macgonuts_release_socket(sockfd);
        return -1;
    }
    if (io_timeo > 0) {
        tv.tv_sec = io_timeo;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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
    char buf[4<<10] = "";
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
    ifp_end = ifp + (ifc.ifc_len / sizeof(ifc));

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
                     max_mac_buf_size - 1, "%.2x:%.2x:%.2x:"
                                           "%.2x:%.2x:%.2x", (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                                                             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                                                             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                                                             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                                                             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                                                             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
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
        macgonuts_si_error("unable to create temporary socket : '%s'\n", strerror(errno));
        return -1;
    }
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
        ifr.ifr_ifindex = -1;
    }
    close(sockfd);
    return ifr.ifr_ifindex;
}

static int set_iface_promisc_flag(const int on, const char *iface) {
    int sockfd = -1;
    struct ifreq ifr = { 0 };
    int err = EFAULT;
    if (iface == NULL) {
        return EINVAL;
    }
    sockfd = socket(AF_INET, SOCK_PACKET, IPPROTO_IP);
    if (sockfd == -1) {
        err = errno;
        goto set_iface_promisc_flag_epilogue;
    }
    strncpy((char *)ifr.ifr_name, iface, strlen(iface));
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) != 0) {
        err = errno;
        goto set_iface_promisc_flag_epilogue;
    }
    if (on) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= (~IFF_PROMISC);
    }
    err = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
set_iface_promisc_flag_epilogue:
    if (sockfd != -1) {
        close(sockfd);
    }
    return err;
}
