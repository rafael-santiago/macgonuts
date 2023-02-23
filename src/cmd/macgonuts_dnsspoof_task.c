/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_dnsspoof_task.h>
#include <cmd/macgonuts_option.h>
#include <macgonuts_status_info.h>

int macgonuts_dnsspoof_task(void) {
    return EXIT_FAILURE;
}

int macgonyts_dnspoof_task_help(void) {
    macgonuts_si_print("use: macgonuts dnsspoof --lo-iface=<label> --target-addrs=<ip4|ip6|cidr4|cidr6 list>\n"
                       "                       [--etc-hoax=<filepath> --hoax-ttl=<secs> --dns-addr=<ip4|ip6>\n"
                       "                        --undo-spoof]\n");
    return EXIT_SUCCESS;
}
