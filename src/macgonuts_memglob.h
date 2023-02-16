/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_MEMGLOB_H
#define MACGONUTS_CMD_MACGONUTS_MEMGLOB_H 1

#include <macgonuts_types.h>

int macgonuts_memglob(const unsigned char *data, const size_t data_size,
                      const unsigned char *pattern, const size_t pattern_size);

#endif
