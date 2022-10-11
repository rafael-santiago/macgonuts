/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_SOCKET_H
#define MACGONUTS_SOCKET_H 1

#include <macgonuts_types.h>

macgonuts_socket_t macgonuts_create_socket(const char *iface, const size_t io_timeo);

void macgonuts_release_socket(const macgonuts_socket_t sockfd);

ssize_t macgonuts_sendpkt(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size);

ssize_t macgonuts_recvpkt(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size);

int macgonuts_get_addr_from_iface(char *addr_buf, const size_t max_addr_buf_size,
                                  const int addr_version, const char *iface);

int macgonuts_get_mac_from_iface(char *mac_buf, const size_t max_mac_buf_size, const char *iface);

int macgonuts_set_iface_promisc_on(const char *iface);

int macgonuts_set_iface_promisc_off(const char *iface);

#endif // MACGONUTS_SOCKET_H

