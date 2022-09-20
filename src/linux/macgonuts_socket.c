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

macgonuts_socket_t macgonuts_create_socket(const char *iface, const int ip_version) {
    struct timeval tv = { 0 };
    int yes = 1;
    macgonuts_socket_t sockfd = -1;
    struct sockaddr_ll sll = { 0 };
    if (ip_version != 4 && ip_version != 6) {
        return -1;
    }
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
