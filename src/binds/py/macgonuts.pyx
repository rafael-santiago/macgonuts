#
# Copyright (c) 2023, Rafael Santiago
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#

""" Macgonuts general spoofing utilities binds for Python """

cdef extern from "macgonuts_pybind.h":
    int macgonuts_pybind_spoof(char *lo_iface, char *target_addr, char *addr2spoof,
                               int fake_pkts_amount, int timeout);

cdef extern from "macgonuts_pybind.h":
    int macgonuts_pybind_undo_spoof(char *lo_iface, char *target_addr, char *addr2spoof);

def macgonuts_spoof(lo_iface, target_addr, addr2spoof, fake_pkts_amount = 1, timeout = 0):
    """The python wrapper for macgonuts_spoof() C function

    By using this function you can easily promote a spoofing attack based on IPv4 or IPv6.

    This function receives:

        - the local interface label (lo_iface)
        - the target IPv4/IPv6 address (target_addr)
        - the IPv4/IPv6 address which will be spoofed at the target host (addr2spoof)
        - the amount of fake address resolution packets to be sent (fake_pkts_amount, its default is one packet only)
        - the timeout amount between the current packet and the next (timeout, its default is no timeout)

    It returns zero on success and non-zero value on failure, besides writing some error description to stderr.
    """
    return macgonuts_pybind_spoof(bytes(lo_iface, 'ascii'),
                                  bytes(target_addr, 'ascii'),
                                  bytes(addr2spoof, 'ascii'),
                                  fake_pkts_amount, timeout)

def macgonuts_undo_spoof(lo_iface, target_addr, addr2spoof):
    """The python wrapper for macgonuts_undo_spoof() C function

    By using this function you can easily undo a previous promoted spoofing attack based on IPv4 or IPV6.

    This function receives:

        - the local interface used during the spoofing attack (lo_iface)
        - the target IPv4/IPv6 address of the spoofing attack (target_addr)
        - the IPv4/IPv6 address which was spoofed at the target host (addr2spoof)

    It returns zero on success and non-zero value on failure, besides writing some error description to stderr.
    """
    return macgonuts_pybind_undo_spoof(bytes(lo_iface, 'ascii'),
                                       bytes(target_addr, 'ascii'),
                                       bytes(addr2spoof, 'ascii'))
