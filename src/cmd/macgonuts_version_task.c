/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_version_task.h>
#include <cmd/macgonuts_version.h>
#include <macgonuts_types.h>
#include <macgonuts_status_info.h>

int macgonuts_version_task(void) {
    macgonuts_si_print("macgonuts "MACGONUTS_CMD_VERSION"\n");
    return EXIT_SUCCESS;
}

int macgonuts_version_task_help(void) {
    macgonuts_si_print("use: macgonuts version\n");
    return EXIT_SUCCESS;
}
