/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_IPCHSUM_H
#define MACGONUTS_IPCHSUM_H 1

#include <macgonuts_types.h>

uint16_t eval_ipchsum(const void *data, const size_t data_size);

#endif
