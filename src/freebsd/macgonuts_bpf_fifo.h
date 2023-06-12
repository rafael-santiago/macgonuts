/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_FREEBSD_BPF_FIFO_H
#define MACGONUTS_FREEBSD_BPF_FIFO_H 1

#include <macgonuts_types.h>

#define MACGONUTS_BPF_BLEN (1<<10)

int macgonuts_bpf_fifo_init(void);

int macgonuts_bpf_fifo_deinit(void);

ssize_t macgonuts_bpf_fifo_enqueue(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size);

ssize_t macgonuts_bpf_fifo_dequeue(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size);

int macgonuts_bpf_fifo_close(const macgonuts_socket_t sockfd);

int macgonuts_bpf_fifo_create(const macgonuts_socket_t sockfd);

#endif // MACGONUTS_FREEBSD_BPF_FIFO_H
