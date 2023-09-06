#!/usr/bin/env python
#
# Copyright (c) 2023, Rafael Santiago
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
# INFO(Rafael): In order to test this sample give it a try:
#                       $ python sample.py
#                               or
#                       $ ./sample.py
#               and so follow the instructions.
#

import macgonuts
import sys

def main():
    if len(sys.argv) < 4:
        sys.stderr.write("use: " + sys.argv[0] + " <iface> <target-ip> <address-to-spoof> "
                         "[ <packets-total> <timeout in mss> ]\n")
        sys.exit(1)

    try:
        packets_total = 1 if len(sys.argv) < 5 else int(sys.argv[4])
    except:
        sys.stderr.write("error: invalid packets-total.\n")
        sys.exit(1)

    try:
        timeout_in_mss = 0 if len(sys.argv) < 6 else int(sys.argv[5])
    except:
        sys.stderr.write("error: invalid timeout-in-mss.\n");
        sys.exit(1)

    if macgonuts.spoof(sys.argv[1], sys.argv[2], sys.argv[3], packets_total, timeout_in_mss) != 0:
        sys.stderr.write("error: while trying to spoof.\n")
        sys.exit(1)

    if macgonuts.undo_spoof(sys.argv[1], sys.argv[2], sys.argv[3]) != 0:
        sys.stderr.write("error: while undoing spoof.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()