/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TYPES_H
#define MACGONUTS_TYPES_H 1

// INFO(Rafael): I have been included system and stdlib headers only here.
//               So every macgonuts module that includes it will fully able
//               to deal with anything inside the library/tool's scope.

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <stdarg.h>
#include <signal.h>

#if defined(__unix__)
# define MACGONUTS_DEFAULT_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif // defined(__unix__)

#define MACGONUTS_VERSION "v1"

#define MACGONUTS_METAINFO_NR 16

typedef int macgonuts_socket_t;

typedef pthread_t macgonuts_thread_t;

typedef pthread_mutex_t macgonuts_mutex_t;

struct macgonuts_spoofing_guidance_ctx;

typedef int (*macgonuts_hook_func)(struct macgonuts_spoofing_guidance_ctx *,
                                   const unsigned char *, const size_t);

typedef int (*macgonuts_printpkt_func)(FILE *,
                                       const unsigned char *, const size_t);

struct macgonuts_filter_glob_ctx {
    unsigned char *glob;
    size_t glob_size;
};

typedef int (*macgonuts_printpkt_if_func)(const unsigned char *, const size_t,
                                          struct macgonuts_filter_glob_ctx **, const size_t);

struct macgonuts_capture_ctx {
    macgonuts_printpkt_func printpkt;
    FILE *pktout;
    macgonuts_printpkt_if_func printpkt_if;
    struct macgonuts_filter_glob_ctx **filter_globs;
    size_t filter_globs_nr;
};

struct macgonuts_spoof_layers_ctx {
    uint8_t lo_hw_addr[6];
    uint8_t tg_hw_addr[6];
    uint8_t spoof_hw_addr[6];
    uint8_t proto_addr_version;
    uint8_t proto_addr_size;
    uint8_t lo_proto_addr[16];
    uint8_t tg_proto_addr[16];
    uint8_t spoof_proto_addr[16];
    unsigned char *spoof_frm;
    size_t spoof_frm_size;
    int always_do_pktcraft;
};

struct macgonuts_spoofing_guidance_ctx {
    struct {
        macgonuts_mutex_t lock;
        macgonuts_thread_t thread;
        macgonuts_socket_t wire;
    } handles;

    struct macgonuts_spoof_layers_ctx layers;

    struct {
        const char *lo_iface;
        const char *tg_address;
        const char *spoof_address;
        char lo_mac_address[18];
        char tg_mac_address[18];
        char spoof_mac_address[18];
    } usrinfo;

    struct {
        int64_t total;
        uint64_t timeout;
        uint8_t abort;
    } spoofing;

    struct {
        macgonuts_hook_func init;
        macgonuts_hook_func deinit;
        macgonuts_hook_func done;
        macgonuts_hook_func redirect;
        struct macgonuts_capture_ctx capture;
    } hooks;

    struct {
        void *arg[MACGONUTS_METAINFO_NR];
    } metainfo;
};

#endif // MACGONUTS_TYPES_H
