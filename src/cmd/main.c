/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_exec.h>

int main(int argc, char **argv) {
    return macgonuts_exec(argc, (const char **)argv);
}
