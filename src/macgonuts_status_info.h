/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_STATUS_INFO_H
#define MACGONUTS_STATUS_INFO_H 1

#include <macgonuts_types.h>

typedef enum {
    kMacgonutsSiSys        = 0x1,
    kMacgonutsSiBuf        = 0x2,
    kMacgonutsSiMonochrome = 0x4,
    kMacgonutsSiColored    = 0x8,
}macgonuts_si_outmode_t;

void macgonuts_si_error(const char *message, ...);

void macgonuts_si_info(const char *message, ...);

void macgonuts_si_warn(const char *message, ...);

void macgonuts_si_set_outmode(const macgonuts_si_outmode_t otype);

int macgonuts_si_get_last_info(char *si_buf, const size_t max_si_buf);

#endif // MACGONUTS_STATUS_INFO
