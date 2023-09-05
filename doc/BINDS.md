# Macgonuts binds

**Abstract**: This document is intended to explain how to use the available `macgonuts` binds.
Details about how to build is not discussed here, take a look at `doc/BUILD.md`.

## Topics

- [What is available until now](#what-is-available-until-now)
- [Using `macgonuts_pybind`](#using-macgonuts_pybind)
- [Using `macgonuts` from `Golang`](#using-macgonuts-from-golang)

## What is available until now

Currently it is only available two function that acts as basic building blocks for managing
spoofing attacks.

Those two function are:

- `macgonuts_spoof()`
- `macgonuts_undo_spoof()`

By using those two functions through the binds, you will be able to easily implement the
spoof stuff at your own program natively without depeding on `macgonuts` command line tool.

Until now `macgonuts` features binds for `Python`.

[``Back``](#topics)

## Using `macgonuts_pybind`

Once it build and well-installed, it is fairly simple to use `macgonuts_pyind` module.
The functions present in this module are:

- `macgonuts_spoof()`
- `macgonuts_undo_spoof()`

The `macgonuts_spoof()` function can receive five arguments:

- `lo_iface` is the name of the interface you are accessing the network.
- `target_addr` is the network address of the target, it can be a `IPv4` or `IPv6` address.
- `addr2spoof` is the address that will be spoofed at target, it can be a `IPv4` or `IPv6` address.
- `fake_pkts_amount` is the total of spoofed packets sent to target, it defaults to one.
- `timeout` is the timeout in `mss` between a spoofed packet and the next, it defauts to no timeout.

The `macgonuts_undo_spoof()` undoes a previous promoted spoof attack against a specific target.
This function expects three arguments:

- `lo_iface` is the name of the interface you are accessing the network.
- `target_addr` is the network address of the target, it can be a `IPv4` or `IPv6` address.
- `addr2spoof` is the address that was spoofed at target, it can be a `IPv4` or `IPv6` address.

Follows the general idea when using `macgonuts` spoofing primitives from `Python`:

```python
import macgonuts_pybind

(...)

# INFO(Rafael): Send one fake ARP packet to 192.168.5.142.
if macgonuts_pybind.macgonuts_spoof('eth0', '192.168.5.142', '192.168.5.1') != 0:
    print('error when trying to spoof.\n');
    (...)

(...)

# INFO(Rafael): Send 200 fake NDP packets to dead::beef:1 at each 500 mss.
if macgonuts_pybind.macgonuts_spoof('eth1',
                                    'dead::beef::8e',
                                    'dead::beef:1', 200, 500) != 0:
    print('error when trying to spoof.\n');
    (...)

(...)

# INFO(Rafael): Now undoing all promoted spoofing attacks.
if macgonuts_undo_spoof('eth0', '192.168.5.142', '192.168.5.1') != 0:
    print('unable to undo spoof attack done from eth0')
    (...)

if macgonuts_undo_spoof('eth1', 'dead::beef:8e', 'dead::beef:1') != 0:
    print('unable to undo spoof attack done from eth1')
    (...)

(...)
```

[``Back``](#topics)

## Using `macgonuts` from `Golang`

Similar to `Python`'s bind you have the two basic building blocks to promote a spoofing attack:

- `Spoof()` function
- `UndoSpoof()` function

The `Spoof()` function expects the following arguments:

- `loIface` is the name of the interface you are accessing the network.
- `targetAddr` is the network address of the target, it can be a `IPv4` or `IPv6` address.
- `addr2Spoof` is the address that will be spoofed at target, it can be a `IPv4` or `IPv6` address.
- `fakePktsAmount` is the total of spoofed packets sent to target, it defaults to one.
- `timeout` is the timeout in `mss` between a spoofed packet and the next, it defauts to no timeout.

Since `Golang` does not have default arguments, when you pass `fakePktsAmount` as zero it will infer
that you want one single fake packet.

The `UndoSpoof()` function expects the following arguments:

- `loIface` is the name of the interface you are accessing the network.
- `targetAddr` is the network address of the target, it can be a `IPv4` or `IPv6` address.
- `addr2Spoof` is the address that was spoofed at target, it can be a `IPv4` or `IPv6` address.

When those function succeed they return `nil` when not, an error is returned and more details are
provided on `stderr`, too.

The bind also implements a `Version()` function that returns a `string` related to the version of the bind.
In general it follows the main version of the project.

This is the main idea on using `Macgonuts` from a `Go` code:

```go
package main

import (
    "fmt"
    "os"
    // INFO(Rafael): Personally I find this way of importing things in Golang kind of naive
    //               and bit stupid. Because you are linking your stuff to on-line stuff from other
    //               people that at some point in the future can remove this, cut access, whatever.
    //               In other words, you have zero control about it. If you lost your local go
    //               installation, maybe in a future attempt of recompiling the stuff you can
    //               be surprised of how external world does not give a sh_t to your dependencies
    //               and you.... If the package is provided by a person, instead of a company, it is
    //               even worse. But even companies can easily vanish away as whole or at least with
    //               some technologies as the years go by. Thus, if you are intending to do good engineering
    //               by writing code that can be built do not mattering where and when... You must consider
    //               my unpopular, "profanus", maybe heretic point....
    "github.com/rafael-santiago/macgonuts/binds/go/v1"
    //               Instead, the better would be cloning the Macgonuts sources and embed it into your
    //               own code, by importing as follows (supposing you are into `binds/go/my-new-blau`:
    "../v1"
    //               Cool off, the stuff is BSD-Licensed! ;)
)

func main() {
    fmt.Printf("Spoofing...\n")
    err := macgonuts.Spoof("eth0", "192.168.5.142", "192.168.5.1", 100, 100)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    fmt.Printf("Done!\nNow Undoing the spoof...\n")
    err = macgonuts.UndoSpoof("eth0", "192.168.5.142", "192.168.5.1")
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    fmt.Printf("Done!\n")
    os.Exit(0)
}
```

You also can check a more complete sample at `src/binds/go/sample`.

[``Back``](#topics)
