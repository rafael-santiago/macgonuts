/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_ETHERCONV_H
#define MACGONUTS_ETHERCONV_H 1

int macgonuts_check_ether_addr(const char *ether, const size_t ether_size);

int macgonuts_getrandom_ether_addr(char *ether, const size_t max_ether_size);

#endif // MACGONUTS_ETHERCONV_H

