#ifndef MACGONUTS_SOCKET_H
#define MACGONUTS_SOCKET_H 1

#include <macgonuts_types.h>

macgonuts_socket_t macgonuts_create_socket(const char *iface);

void macgonuts_release_socket(const macgonuts_socket_t sockfd);

ssize_t macgonuts_sendpkt(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size);

ssize_t macgonuts_recvpkt(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size);

#endif
