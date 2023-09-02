/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONTUS_BINDS_PY_MACGONUTS_PYBIND_H
#define MACGONUTS_BINDS_PY_MACGONUTS_PYBIND_H 1

int macgonuts_pybind_spoof(char *lo_iface, char *target_addr, char *addr2spoof,
                           int fake_pkts_amount, int timeout);

int macgonuts_pybind_undo_spoof(char *lo_iface, char *target_addr, char *addr2spoof);

#endif // MACGONUTS_BINDS_PY_MACGONUTS_PYBIND_H
