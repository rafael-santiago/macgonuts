/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>
#include <macgonuts_status_info.h>
#include <binds/macgonuts_binds.h>


int macgonuts_pybind_spoof(char *lo_iface, char *target_addr, char *addr2spoof,
                           int fake_pkts_amount, int timeout) {
    if (lo_iface == NULL
        || target_addr == NULL
        || addr2spoof == NULL || fake_pkts_amount <= 0) {
        macgonuts_si_error("invalid argument(s) passed to macgonuts_pybind_spoof().\n");
        return EXIT_FAILURE;
    }

    return macgonuts_binds_spoof(lo_iface, target_addr, addr2spoof, fake_pkts_amount, timeout);
}

int macgonuts_pybind_undo_spoof(char *lo_iface, char *target_addr, char *addr2spoof) {
    if (lo_iface == NULL
        || target_addr == NULL
        || addr2spoof == NULL) {
        macgonuts_si_error("invalid argument(s) passed to macgonuts_pybind_undo_spoof().\n");
        return EXIT_FAILURE;
    }

    return macgonuts_binds_undo_spoof(lo_iface, target_addr, addr2spoof);
}
