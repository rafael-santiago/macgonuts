/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_BINDS_MACGONUTS_BINDS_H
#define MACGONUTS_BINDS_MACGONUTS_BINDS_H 1

int macgonuts_binds_spoof(char *lo_iface, char *target_addr, char *addr2spoof,
                           int fake_pkts_amount, int timeout);

int macgonuts_binds_undo_spoof(char *lo_iface, char *target_addr, char *addr2spoof);

#endif // MACGONUTS_BINDS_MACGONUTS_BINDS_H
