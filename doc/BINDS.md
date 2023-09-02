# Macgonuts binds

**Abstract**: This document is intended to explain how to use the available `macgonuts` binds.
Details about how to build is not discussed here, take a look at `doc/BUILD.md`.

## Topics

- [What is available until now](#what-is-available-until-now)
- [Using `macgonuts_pybind`](#using-macgonuts_pybind)

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
