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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>

#define MACGONUTS_VERSION "v1"

typedef int macgonuts_socket_t;

#endif // MACGONUTS_TYPES_H
