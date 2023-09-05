//
// Copyright (c) 2023, Rafael Santiago
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.
//
// INFO(Rafael): If you want to build this sample just run `go build`
package main

import (
	"../v1"
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "use: %s <iface> <target-ip> <address-to-spoof> [ <packets-total> <timeout in mss> ]",
			os.Args[0])
		os.Exit(1)
	}
	var packetsTotal int = 0
	var err error = nil
	if len(os.Args) > 4 {
		packetsTotal, err = strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if packetsTotal < 0 {
			fmt.Fprintf(os.Stderr, "error: packets-total must be a positive integer.\n")
			os.Exit(1)
		}
	}
	var timeoutInMss int = 0
	if len(os.Args) > 5 {
		timeoutInMss, err = strconv.Atoi(os.Args[5])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if timeoutInMss < 0 {
			fmt.Fprintf(os.Stderr, "error: timeout must be a positive integer.\n")
			os.Exit(1)
		}
	}
	err = macgonuts.Spoof(os.Args[1], os.Args[2], os.Args[3], packetsTotal, timeoutInMss)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = macgonuts.UndoSpoof(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}
