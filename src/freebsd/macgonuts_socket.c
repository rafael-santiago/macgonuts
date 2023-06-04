/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_socket.h>
#include <freebsd/macgonuts_bpf_fifo.h>
#include <macgonuts_status_info.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <sys/types.h>
#include <errno.h>

static int set_iface_promisc_flag(const int on, const char *iface);

int macgonuts_set_iface_promisc_on(const char *iface) {
    return set_iface_promisc_flag(1, iface);
}

int macgonuts_set_iface_promisc_off(const char *iface) {
    return set_iface_promisc_flag(0, iface);
}

macgonuts_socket_t macgonuts_create_socket(const char *iface, const size_t io_timeo) {
    char bpfdev[20] = "";
    int devno = 0;
    struct ifreq bound_if;
    macgonuts_socket_t sockfd = -1;
    int sk_flags = 0;
    int err = EXIT_FAILURE;

    memset(&bound_if, 0, sizeof(bound_if));

    do {
        snprintf(bpfdev, sizeof(bpfdev) - 1, "/dev/bpf%d", devno);
        sockfd = open(bpfdev, O_RDWR | O_SHLOCK);
        if (sockfd == -1) {
            devno++;
        }
    } while (devno < 255 && sockfd == -1);

    if (sockfd == -1) {
        macgonuts_si_error("unable to find out a /dev/bpf device.\n");
        goto macgonuts_create_socket_epilogue;
    }

    sk_flags = fcntl(sockfd, F_GETFL);
    fcntl(sockfd, sk_flags | O_NONBLOCK);
    strncpy(bound_if.ifr_name, iface, sizeof(bound_if.ifr_name) - 1);
    if (ioctl(sockfd, BIOCSETIF, &bound_if) == -1) {
        macgonuts_si_error("unable to bind raw socket : '%s'\n", strerror(errno));
        goto macgonuts_create_socket_epilogue;
    }

    sk_flags = 1;
    if (ioctl(sockfd, BIOCIMMEDIATE, &sk_flags) == -1) {
        macgonuts_si_error("unable to set bpf socket to immediate mode : '%s'\n", strerror(errno));
        goto macgonuts_create_socket_epilogue;
    }

    if (ioctl(sockfd, BIOCGBLEN, &sk_flags) == -1) {
        macgonuts_si_error("unable to set get buffer size capability for bpf socket : '%s'\n", strerror(errno));
        goto macgonuts_create_socket_epilogue;
    }

    err = macgonuts_bpf_fifo_create(sockfd);

macgonuts_create_socket_epilogue:

    if (err != EXIT_SUCCESS && sockfd > -1) {
        close(sockfd);
        sockfd = -1;
    }

    return sockfd;
}

void macgonuts_release_socket(const macgonuts_socket_t sockfd) {
    if (macgonuts_bpf_fifo_close(sockfd) != EXIT_SUCCESS) {
        macgonuts_si_warn("unable to close BPF socket descriptor fifo.\n");
    }
    close(sockfd);
}

int macgonuts_get_mac_from_iface(char *mac_buf, const size_t max_mac_buf_size, const char *iface) {
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *ip = NULL;
    uint8_t *hw_addr = NULL;
    int err = EFAULT;

    if (getifaddrs(&ifap) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    for (ip = ifap; ip != NULL && err != EXIT_SUCCESS; ip = ip->ifa_next) {
        if (strcmp(ip->ifa_name, iface) != 0) {
            continue;
        }
        if (ip->ifa_data != NULL
            && ip->ifa_addr->sa_family == AF_LINK) {
            hw_addr = (uint8_t *)LLADDR((struct sockaddr_dl *)ip->ifa_addr);
            snprintf(mac_buf, max_mac_buf_size - 1, "%.2x:%.2x:%.2X:"
                                                    "%.2x:%.2x:%.2x", hw_addr[0], hw_addr[1], hw_addr[2],
                                                                      hw_addr[3], hw_addr[4], hw_addr[5]);
            err = EXIT_SUCCESS;
        }
    }

    freeifaddrs(ifap);

    return err;
}

ssize_t macgonuts_sendpkt(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size) {
    return macgonuts_bpf_fifo_enqueue(sockfd, buf, buf_size);
}

ssize_t macgonuts_recvpkt(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size) {
    return macgonuts_bpf_fifo_dequeue(sockfd, buf, buf_size);
}

static int set_iface_promisc_flag(const int on, const char *iface) {
    int if_sock = -1;
    struct ifreq bound_if;
    int err = EFAULT;

    if (iface == NULL) {
        return EINVAL;
    }

    if_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (if_sock == -1) {
        goto set_iface_promisc_flag_epilogue;
    }

    memset(&bound_if, 0, sizeof(bound_if));
    strncpy(bound_if.ifr_name, iface, IFNAMSIZ);

    if (ioctl(if_sock, SIOCGIFFLAGS, &bound_if) != 0) {
        goto set_iface_promisc_flag_epilogue;
    }

    if (on) {
        bound_if.ifr_flagshigh |= IFF_PPROMISC >> 16;
    } else {
        bound_if.ifr_flagshigh &= ~(IFF_PPROMISC >> 16);
    }

    err = (ioctl(if_sock, SIOCSIFFLAGS, &bound_if) < 0) ? EXIT_FAILURE : EXIT_SUCCESS;

set_iface_promisc_flag_epilogue:

    if (if_sock != -1) {
        close(if_sock);
    }

    return err;
}
