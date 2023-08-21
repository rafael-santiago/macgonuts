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
    - [The dnsspoof command](#the-dnsspoof-command)
    - [The xablau command](#the-xablau-command)
    - [The caleaboqui command](#the-caleaboqui-command)

## What does ``macgonuts`` is for?

Besides a lousy pun, ``macgonuts`` is also a tool to exploit address resolution on networks.
Anyway, the main motivation to implement ``macgonuts`` was the possibility of using the lousy pun, I need to admit...
You can also understand ``macgonuts`` as a swiss army knife to exploit address resolution on computer networks, but
my main goal was to have something to use the pun.

[``Back``](#topics)

## Basic facts about the command line tool

1. This is about a ``unix-like`` tool.
2. It does not set on fireworks when a thing works.
3. It is based on commands.
4. When you want a quick help about a command you run: ``macgonuts help <command>``.
5. If you do not want to read this manual by preferring poke the tool by yourself: ``macgonuts help``.
6. If you still do not understand, try to go to 1 (repeat it some couple of times).
7. Open an issue asking me about, thank you for helping me to improve on the documentation! :wink:

[``Back``](#topics)

## Commands

This section describes in details all implemented commands in ``macgonuts``. Keep on reading to master up
the tool and making a youtube video about it (because I do not have any talent or even patience to do this),
many thanks in advance! :satisfied:

### The spoof command

>Maybe the ``spoof`` command is the command what you arrived here for. With ``spoof`` command you can deceive
a host by making it thinks that you are the droid that it was looking for...

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

Nice, it does support ``ARP`` and ``NDP`` because options related to addressing stuff supports ``ipv4`` or ``ipv6``!

The option ``lo-iface`` stands for "local interface", thus you need to indicate the interface that your
machine uses to access the network that you are wanting to.. err... mess up... The option ``target-addr``
is where you indicate the address of the host that you want to deceive and ``addr2spoof`` option is where
you input the address that you want to override in target host system.

Now, story time!!!!!!

Once upon time, three persons: Alice, Bob and Eve... How creative, huh?

- Alice is on host ``192.30.70.8``.
- Bob is on host ``192.30.70.10``.
- Eve is on host ``192.30.70.9``.

Eve wants to use ``macgonuts`` to make Bob thinks that she is Alice in the network. So Eve runs:

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
In fact, the spoof is done and, at this moment ``192.30.70.10`` (Bob) thinks that ``192.30.70.8`` (Alice) is
``192.30.70.9`` (Eve).

If Eve wants to avoid flooding the network with so many packets she can pass ``timeout=<mss>`` option:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500
```

The same effect of the prior command but now at each half second ``macgonuts`` will inject in the network one
fake ``ARP`` resolution.

Nice, but Eve also wants to avoid interrupting any communication between ``Alice <-> Bob``, in this way, she can sit on
and eavesdropping (what a nice pun, huh?!) their channel. It can be done by passing ``redirect`` flag:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=500 --redirect
```

Same effect, still spoofed but now redirecting packets and it does not abuse the network throughput.

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

If flooding network is not an option, Eve also could send only a specific amount of fake resolution
packets by using ``fake-pkts-amount=<n>``:

```
eve@RestaurantAtTheEndOfTheUniverse:~# macgonuts spoof --lo-iface=eth1 \
> --target-addr=192.30.70.10 --addr2spoof=192.30.70.8 --timeout=3000 --fake-pkts-amount=50
> --redirect --undo-spoof
```

**Tip**: When you do redirect it has already some implicit timeout, thus, maybe you do not have to pass an
explicit timeout, depending on how much of timeout you are intending between fake resolution packets.

Congrats! Now you are a ``macgonuts spoofing`` master!

[``Back``](#topics)

### The eavesdrop command

>If you are wanting to do some active sniffing between two points this is the ``macgonuts`` command that you are
looking for...

With ``eavesdrop`` command you are able to simply watch the network traffic or log it to later inspection. You can
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

Eve, after some "evil" laughs (``- MuHahuahuahuAH...``, ``- Muhahauahuahau...``) however, she was using ``macgonuts``
that has btw her favorite command that is able to deceive bridged/segmented networks when sniffing (Well, I love puns,
I have to admit).

All Eve did:

```
eve@FarEastForTheTrees:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12
```

After that, all what the two talked each other begun be displayed at Eve's screen. Nice!

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
log only what should be abuses on her corporate network environment:

```
eve-the-sysadmin-with-lasers-and-very-silent@Tender:~# macgonuts eavesdrop --lo-iface=eth1 \
> --alice-addr=192.30.70.11 --bob-addr=192.30.70.12 --pcap-file=log-them-tender-log-them-switch.pcap \
> --filter-globs=*xxx.org*,*\x03xxx\x3org*,*[Rr][Ii][Cc][Kk][Rr][Oo][Ll]* --undo-spoof

```

As you can see ``filter-globs`` option supports extended asciis by passing its values as hexadecimal
numbers in form ``\xXX``. The glob supports the classical wildcards: star (``*``), question (``?``) and
groups (``[...]``). It is also possible to pass longer hexadecimal streams, e.g: ``\x45007238123731627320``.

Congrats again! Welcome to the paradise, now you are a ``macgonuts eavesdrop`` master.

[``Back``](#topics)

### The isolate command

>With the isolate command it is possible to make a specific host an island. Any contact done from anyone in the
local network will be "cut off" by letting that target alone.

If you ask the quick help of the isolate command you will get the following:

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

In this case all between ``192.30.70.1-192.30.70.15`` and ``192.30.70.60`` will be unreachable from
John's host (``192.30.70.8``).

Congrats! Now you are a ``macgonuts`` troll master by knowing every single thing about
``macgonuts isolate`` command!

[``Back``](#topics)

### The mayhem command

>If you are only seeking to annoy a network as whole, maybe the mayhem command is the command for you.
With mayhem you are able to make `ARP/Neighbor` tables a total mess. As a result the host will be unable
to communicate each other or at least unable to communicate each other without unstability.

In order to work on this command needs three basic options:

1. The local interface.
2. A CIDR.
3. A list of targets.

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

Mallory also could be defined a timeout when sending out those fake MAC resolution packets by using
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

### The dnsspoof command

> If you are finding a way of redirecting some host to another by making this host accept fake name resolutions, dnsspoof
is your command of choice...

Let's take a look at ``dnsspoof`` quick help:

```
ulisses@cave:~# macgonuts help dnsspoof
use: macgonuts dnsspoof --lo-iface=<label> --target-addrs=<ip4|ip6 list>
                       [--etc-hoax=<filepath> --hoax-ttl=<secs> --dns-addrs=<ip4|ip6 list>
                        --undo-spoof]
```

Well, by default ``dnsspoof`` command expects at least two options:

- ``lo-iface``
- ``target-addrs``

Being ``lo-iface`` option the name of your network interface card, the ``NIC`` that you will use during the
``DNS spoof attack`` and, ``target-addrs`` is just about an ip address listing that will be the potential
targets of this attack.

The core of ``dnsspoof`` command is a special file called (drum roll, one more lousy pun) `/etc/hoax`. It is similar to
your nearest ``/etc/hosts`` file. By default ``macgonuts`` will install a default copy of ``/etc/hoax`` but you need to tune it up
according to your interests (the default installation path is ``/usr/local/share/macgonuts/etc/hoax``).
When you do not make the location of the ``/etc/hoax`` explicit by using ``etc-hoax`` option, ``macgonuts``
will try to use the installed default one.

The syntax of a ``/etc/hoax`` is as follows:

```
# IPv6 or IPv4 address          FQDN or a glob based on a FQDN, btw, this is a commentary! ;)

2001:db8:0:f101::2              faketory.fakebook.com
2001:db8:0:f101::3              *.fakebook.com
8.8.8.8                         *.fakebook.com
```

As you see, it is quite similar to ``/etc/hosts``. The ``dnsspoof`` command will use the address mappings present
in passed ``/etc/hoax`` to base all ``DNS`` resolutions that will deceive the attacking victims.

Now, story time!!!!!!

Once upon time, three users in a local network environment: ``ulisses``, ``polifemo`` and ``ninguém``.

Facts about the network configuration:

- ``Ulisses``'s address is ``192.168.5.111`` and his host name at the local network is ``ulisses.lo``
- ``Polifemo``'s address is ``192.168.5.142`` and his host name at the local network is ``polifemo.lo``
- ``Ninguém``'s address is ``192.168.5.171`` and his host name at the local network is ``ninguem.lo``
- The gateway address is ``192.168.5.1``.

``Ulisses`` knows that ``Polifemo`` is always seeking to troll him host up at this local network. So ``Ulisses`` want to
make ``Polifemo`` thinks that he is ``Ninguém``. Well, since everyone access the computer from the others by using names
instead of raw IPs, ``Ulisses`` decided to use ``macgonuts dnsspoof``.

So ``Ulisses`` tuned the following ``/etc/hoax`` up:

```
192.168.5.171           ulisses.lo
```

He saved it as ``/tmp/i_am_ninguem`` and executed ``macgonuts`` as follows:

```
ulisses@cave:~# macgonuts dnsspooof --lo-iface=eth0 --target-addrs=192.168.5.142 \
> --etc-hoax=/tmp/i_am_ninguem
```

All done! From now on any ``DNS`` query sent by ``Polifemo`` trying to discover where is ``ulisses.lo`` will
be replied with a fake resolution telling that ``ulisses.lo`` is at ``192.168.5.171`` (``ninguem.lo``).

But the resolutions will last only ``1s``, if he want that it lasts more he can use ``hoax-ttl`` option
by indicating the duration in seconds:

```
ulisses@cave:~# macgonuts dnsspooof --lo-iface=eth0 --target-addrs=192.168.5.142 \
> --etc-hoax=/tmp/i_am_ninguem --hoax-ttl=3600
```

Now the resolutions should last for 1 hour in ``Polifemo``'s dns cache (but it also depends on his operating system policy).

Anyway, ``Polifemo`` has some friends in this network that should annoy ``Ulisses``, too. In this way, ``Ulisses``
only have to indicate the ip addresss of each:

```
ulisses@cave:~# macgonuts dnsspooof --lo-iface=eth0 \
> --target-addrs=192.168.5.142,192.168.5.143,192.168.5.144,192.168.5.145 \
> --etc-hoax=/tmp/i_am_ninguem --hoax-ttl=3600
```

Now the hosts from ``192.168.5.142`` to ``192.168.5.145`` when trying to reach ``Ulisses`` by his
host name will reach ``Ninguém``.

But ``Ulisses`` is smart and does not want to warn them of his ``FQDN escapade``. Supposing that ``ulisses.lo``
goes off, it does not necessarily will do ``ninguem.lo`` goes off too, and, it could alarm ``Polifemo`` and his not
so clever gang... Trying to make his fakery more perfect, ``Ulisses`` uses ``undo-spoof`` option:

```
ulisses@cave:~# macgonuts dnsspooof --lo-iface=eth0 \
> --target-addrs=192.168.5.142,192.168.5.143,192.168.5.144,192.168.5.145 \
> --etc-hoax=/tmp/i_am_ninguem --hoax-ttl=3600 --undo-spoof
```

Now when ``Ulisses`` exits ``macgonuts``, it will undo all spoofing dance done under the hood.

Let's suppose that ``Ulisses`` now also want to ``hack`` ``Polifemo`` and his gang with some
``phising attack``. Knowing that ``Polifemo`` and folks are really busy people, Ulisses prepared some
meaningful fake web pages at ``192.168.5.101`` and updated his ``/tmp/i_am_ninguem`` to:

```
192.168.5.171           ulisses.lo
# Busy people...
192.168.5.101           *.facebook.com
192.168.5.101           *.twitter.com
192.168.5.101           *.instagram.com
192.168.5.101           *.tiktok.com
192.168.5.101           *.kwai.com
```

Now supposing that this network start using an internal ``DNS`` at ``192.168.5.8``. All ``Ulisses`` must do
is indicate the internal ``DNS`` address in ``dns-addrs`` list:

```
ulisses@cave:~# macgonuts dnsspooof --lo-iface=eth0 \
> --target-addrs=192.168.5.142,192.168.5.143,192.168.5.144,192.168.5.145 \
> --dns-addrs=192.168.5.8 \
> --etc-hoax=/tmp/i_am_ninguem --hoax-ttl=3600 --undo-spoof

```

By the way, it will make the attack easier to promote. The ``dns-addrs`` option is also useful when you want
to spoof ``DNS`` replies that come from a specify ``DNS`` server (even external).

Did you see as easy is to promote a ``DNS`` spoof attack with ``macgonuts``? You do not need to pile up ``n`` tools,
emit ``OS`` commands to your network stack etc. You should just inform the context of your attack... e tchum! [sic]

``dnsspoof`` was a reborn of ``dnsf_ckr``. A tool of mine that I wrote some couple of years ago but it had a lot of
"operational gaps". This reborn works as I wanted since that time and it still supports ``IPv6`` environments! :metal:

Congrats! Now you are a master of ``FQDN`` forgery and falsehoods with ``macgonuts dnsspoof`` command! ``Geppetto`` is
proud of you ``Pinocchio``! You nasty busybody... Use it with care!

[``Back``](#topics)

### The xablau command

>If you are looking around for possible targets to your offensive actions, maybe ``macgonuts`` features
one command to do it and, this command is...

<h1 align="center">X    A    B    L    A    U    !</h1>

<p align="center">
    <img src="https://github.com/rafael-santiago/macgonuts/blob/main/etc/xablau.gif" title="xablau is the key!"
     alt="XABLAU" width="320" height2="200" />
</p>

By using ``xablau`` you are able to discover all reachable nodes that could be potential targets to your
``layer-2`` misconducts and, there is not much secret on using it but: story time!!!!

Once upon time ``Trollman Burbank`` was looking for targets to have some fun with ``macgonuts``. He had
just ingress into your hotel network by getting a valid ``IP`` but he knew nothing about other hosts.
Someone tell him to use a weird command called "xablau". "- Xa who?" he said... Even so, he gave ``xablau``'s
quick help a try:

```
tr011m4n@e||TV:~# macgonuts help xablau
use: macgonuts xablau --lo-iface=<label> [--ipv4 --ipv6 --oui --oui-dbpath=<filepath> --out=<filepath>]
```

Hmmm, nice, he knew that his system was using ``eth4`` to access your ``LAN`` besides also know that this local
network was about an ``IPv4`` network. So he ran the following ``xablau``:

```
tr011m4n@e||TV:~# macgonuts xablau --lo-iface=eth4 --ipv4
```

After a time ``macgonuts`` started discovering some network nodes and listing it to ``Trollman``:

```
tr011m4n@e||TV:~# macgonuts xablau --lo-iface=eth4 --ipv4
(...)
IP Address           MAC Address
--------------------------------------
192.168.2.1          08:71:B8:C3:FF:0B
192.168.2.10         DE:AD:00:00:BE:EF
192.168.2.42         BE:EF:00:00:DE:AD
192.168.2.128        7E:57:E0:7E:57:E0
192.168.2.192        CA:FE:FE:D1:DA:00
192.168.2.242        BE:BA:CA:FE:CA:FE
--------------------------------------
```

Okay, but Trollman was also accessing an ``IPv6`` local network through ``eth6`` interface. He also wanted
to have some fun with this ``IPv6``:

```
tr011m4n@e||TV:~# macgonuts xablau --lo-iface=eth6 --ipv6
(...)
IP Address                               MAC Address
----------------------------------------------------------
2001:db8:0:f101::3                       08:00:27:97:64:91
----------------------------------------------------------
```

Now, nice facts about ``xablau`` command:

- ``Trollman`` could have interrupted the process of discovering any time just by hitting ``Ctrl + C``, too.
- ``Trollman`` could have redirected the discovering output to a file by using ``--out=<filepath>`` option and,
  the output would be appended to this indicated file.
- If ``Trollman`` would not have passed ``--ipv4`` option, ``macgonuts`` would try all addressing versions available for the
  indicated interface. I meant ``IPv4`` and/or ``IPv6``.
- So passing ``--ipv4`` and ``--ipv6`` is a thing that in Portuguese we say "perfunctório", do not do that. ``Macgonuts``
  will understand that you want both when you pass none...

Now maybe you are asking: is there something more that I should known about ``xablau``? Well...

<p align="center">
    <img src="https://github.com/rafael-santiago/macgonuts/blob/main/etc/oui.gif" title="puns, puns, lousy puns!!!"
     alt="OUI" width="320" height2="200" />
</p>

If you want to get information about vendor of the prey ``NICs`` found out in your ``LAN``, the ``--oui`` option
is what you are looking for:

```
tr011m4n@e||TV:~# macgonuts xablau --lo-iface=eth0 --ipv4 --oui
(...)
IP Address           MAC Address                       Vendor
----------------------------------------------------------------------------------------------------
192.168.5.1          D8:77:01:19:91:BD                 Intelbras
----------------------------------------------------------------------------------------------------
```

By default, ``macgonuts`` will use the standard installed ``OUI`` database at ``/usr/local/share/macgonuts/etc/oui``.
If you want to override it, you can pass the path of the new database by using ``--oui-dbpath=<filepath>``.

Done! Now you know how to sniff your prey through the wire. You are a ``xablau`` master!

Maybe you are still asking ``WTF "xablau" does mean??!``. ``Xablau`` is a kind of "meta-expression" that I picked
from one brazilian TV show favorite of mine, called ``Larica Total``. A kind of tribute for the best food TV show
in the Universe. A no-frills food TV show I would say... If you did not understand, relax, ``xablau`` is ``xablau``
and even, not knowing, you are from now on a ``f_cking-amazing-macgonuts-xablau-master``. Congrats!

Anyway, if jot down `xablau` is too much for you, you can try its well behaved alias: `neighscan`.

[``Back``](#topics)

### The caleaboqui command

> If there is someone in your network consuming all `Internet` bandwidth getting in the way your downloads... you can
drive away this noisy host from your gateway (wait... `_ modprobe -rf euphemism`) err... You can cut off its
`Internet` access and with it rip off all this bandwidth slice all to you :trollface:, :godmode:!

In order to achive this misconduct with `macgonuts` all you need is:

<p align="center">
    <img src="https://github.com/rafael-santiago/macgonuts/blob/main/etc/keep_calm_and_caleaboqui.jpg" title="shhh..."
     alt="CALEABOQUI!" width="320" height2="200" />
</p>

Using `caleaboqui` you will be able to make a host from your local network "forget" how to find out a way
to the `Internet` and by doing it the noisy person or even device will be silented out and as a result freeing up
bandwidth. Simple but a little egoistic I would say and you need to admit!

So... you are used to already: Story time!!!!

Once upon time `Narciso`, he was trying to save all the `Internet` to your local network but there was `Pär-hot` in his way,
`Pär-hot Diesel` was addicted to `Internet` websites with names starting with three X's, well... you understood.

The problem was that `Pär-hot Diesel` was consuming a bunch of network bandwidth from your host `192.168.5.69` and
`Narciso` at host `192.168.5.101` was not getting much from his network gateway a.k.a `192.168.5.1`. Making far from
impossible his quixotic "Let's Save The Internet!" task...

Facing that `Narciso` has decided be an inedit thing: egoistic. He remembered that his system had `macgonuts` installed
and that this tool has a strange but useful `egoistic` command: `"caleaboqui"`. That by the way he has been in love since
them buuuut not so much... Because his love was really destined to another well known person... Well, well...

Anyway, `Narciso` simply called `macgonuts` requesting from it `caleaboqui`'s quick help:

```
Narciso@s0m3l4k3:~# macgonuts help caleaboqui
use: macgonuts caleaboqui | shh --lo-iface=<label> --target-addrs=<ip4|ip6|cidr4|cidr6 list>
                            [--undo-spoof --hide-my-ass --timeout=<ms> --fake-pkts-amount=<ms> --spoof-threads=<n>]
```

Nice, he knows that he was accessing his local network through `eth0` interface. Thus all he did was:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.69
```

Done! His screen was flooded with a bunch of info saying that `Internet` access of `Pär-hot Diesel` had been cut off.
For sure from that time the gateway overhead got lower. `Narciso` had the whole bandwidth to him to save the
whole `Internet` in your workstation: `all-just-2-&&-4-him`...

But supposing that `Narciso` wanted be nice with his system and network giving them a time to breath between the
cutting off operation... All he should use was `--timeout=<mss>` option:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.69 \
> --timeout=3000
```

It would inject fake resolutions in the local network and wait for `3 seconds` before doing it again.

`Narciso` also would take care of staying incognito by using `--hide-my-ass` option:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.69 \
> --timeout=3000 --hide-my-ass
```

By using `--hide-my-ass` the target host will be informed to access random `MAC` addresses instead of yours,
when trying to talk to the "external world".

However, the work of staying really incognito requires two options. One is `--hide-my-ass` and the another is `--undo-spoof`:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.69 \
> --timeout=3000 --hide-my-ass --undo-spoof
```

When passed `--undo-spoof` `macgonuts` will take care of restablishing the `Internet` access when exiting. In
this way people will think that the lack of access to `Internet` was momentaneous.

Oh yes: to exit `caleaboqui` only hit `Ctrl + C`.

The option `--target-addrs` also supports `CIDR` ranges. So you can cut off `Internet` access from all hosts
currently on. Let's suppose that `Narciso` wanted to ensure that nobody besides him access `Internet`:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.0/24
```

In this case it was about a common `class C` local net (`255.255.255.0`).

It take us to important things to take into consideration when cutting `Internet` of inferred hosts from a `CIDR`:

- By default `macgonuts` will send out `five` fake packets to the found out targets.
- It will use only one spoofing thread.
- It will avoid messing with your own host and the network gateway.
- You can hide your ass but you cannot restablish the `Internet` access of the targets when exiting `macgonuts`.

If you want to traverse the `CIDR` more efficiently you should pass `--spoof-threads=<n>` option.
This option defines the amount of concurrent spoofing tasks, so you can attack more
than one target simultaneously, take a look:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.0/24 \
> --spoof-threads=32
```

If you want to change the quantity of `five` fake packets sent out to targets, use `--fake-pkts-amount`:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.0/24 \
> --spoof-threads=32 --fake-pkts-amount=42
```

Anyway, if you want a more efficient `Internet` cutting off, try to pass `unicast` targets:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.69,192.168.5.169
```

If your network interface is configured with `IPv4` and `IPv6` you are able to handle those different network
protocol versions with a single `macgonuts` process:

```
Narciso@s0m3l4k3:~# macgonuts caleaboqui --lo-iface=eth0 --target-addrs=192.168.5.69,dead::beef:45 \
> --timeout=500 --hide-my-ass --undo-spoof

```

Maybe you are asking:

> - Man, why this strange name, "caleaboqui"?

Well, `caleaboqui` was picked from a famous `redub` done by a `Brazilian` comedy group called `Hermes e Renato`.
"caleaboqui" is a wrong form of "cale a boca" (said by people that talks bad portuguese, or even a slang form) it
does mean `shut up`. If `caleaboqui` is too much for you, I would suggest you `shh` :bowtie: :smirk:

[``Back``](#topics)
