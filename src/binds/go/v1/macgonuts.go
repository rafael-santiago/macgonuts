//
// Copyright (c) 2023, Rafael Santiago
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.
//
package macgonuts

/*
#cgo CFLAGS: -I../../..
#cgo LDFLAGS: -L../../../../lib -L../../../libs/accacia/lib -lmacgonuts -lmacgonutssock -laccacia
#include <binds/macgonuts_binds.h>
#include <binds/macgonuts_binds.c>
*/
import "C"
import "unsafe"

import (
	"fmt"
)

// The Golang bind for macgonuts_spoof() function from libmacgonuts.
// By using this function you can easily promote a spoofing attack based on IPv4 or IPv6. It receives:
// - the local interface label (loIface)
// - the target IPv4/IPv6 address (targetAddr)
// - the IPv4/IPv6 address which will be spoofed at the target host (addr2Spoof)
// - the amount of fake address resolution packets to be sent (fakePktsAmount, when zero it defaults to one)
// - the timeout amount between the current packet and the next (timeout, its default is no timeout)
// It returns nil on success and an error on failure, besides writing some error description to stderr.
func Spoof(loIface, targetAddr, addr2Spoof string, fakePktsAmount, timeout int) error {
	if len(loIface) == 0 || len(targetAddr) == 0 || len(addr2Spoof) == 0 {
		return fmt.Errorf("invalid argument(s) passed to MacgonutsSpoof().")
	}
	lo_iface := C.CString(loIface)
	defer C.free(unsafe.Pointer(lo_iface))
	target_addr := C.CString(targetAddr)
	defer C.free(unsafe.Pointer(target_addr))
	addr2spoof := C.CString(addr2Spoof)
	defer C.free(unsafe.Pointer(addr2spoof))
	var fake_pkts_amount C.int = 1
	if fakePktsAmount > 0 {
		fake_pkts_amount = C.int(fakePktsAmount)
	}
	if C.macgonuts_binds_spoof(lo_iface,
		target_addr,
		addr2spoof, fake_pkts_amount, C.int(timeout)) != 0 {
		return fmt.Errorf("error when spoofing.")
	}
	return nil
}

// The Golang bind for macgonuts_undo_spoof() function from libmacgonuts.
// By using this function you can easily undo a previous promoted spoofing attack based on IPv4 or IPV6. It receives:
// - the local interface used during the spoofing attack (loIface)
// - the target IPv4/IPv6 address of the spoofing attack (targetAddr)
// - the IPv4/IPv6 address which was spoofed at the target host (addr2Spoof)
// It returns zero on success and non-zero value on failure, besides writing some error description to stderr.
func UndoSpoof(loIface, targetAddr, addr2Spoof string) error {
	if len(loIface) == 0 || len(targetAddr) == 0 || len(addr2Spoof) == 0 {
		return fmt.Errorf("invalid argument(s) passed to MacgonutsSpoof().")
	}
	lo_iface := C.CString(loIface)
	defer C.free(unsafe.Pointer(lo_iface))
	target_addr := C.CString(targetAddr)
	defer C.free(unsafe.Pointer(target_addr))
	addr2spoof := C.CString(addr2Spoof)
	defer C.free(unsafe.Pointer(addr2spoof))
	if C.macgonuts_binds_undo_spoof(lo_iface, target_addr, addr2spoof) != 0 {
		return fmt.Errorf("error when undoing spoof.")
	}
	return nil
}

// Returns the version of the bind stuff.
func Version() string {
	return C.MACGONUTS_VERSION
}
