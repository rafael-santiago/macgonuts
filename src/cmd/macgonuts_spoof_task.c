/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_spoof_task.h>
#include <macgonuts_status_info.h>

int macgonuts_spoof_task(void) {
    return EXIT_FAILURE;
}

int macgonuts_spoof_task_help(void) {
    macgonuts_si_print("use: macgonuts spoof --lo-iface=<local-interface> "
                       "--target-addr=<addr> --addr2spoof=<addr> [--fake-pkts-amount=<n>]\n");
    return EXIT_SUCCESS;
}
