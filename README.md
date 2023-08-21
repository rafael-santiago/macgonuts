# Macgonuts ![ci-status](https://github.com/rafael-santiago/macgonuts/actions/workflows/forge-specs.yml/badge.svg)

![linux-function-coverage](https://img.shields.io/badge/function_coverage-95.9%25-lime?logo=linux&logoColor=white&style=plastic) ![linux-line-coverage](https://img.shields.io/badge/line_coverage-84.3%25-lime?logo=linux&logoColor=white&style=plastic) ![freebsd-function-coverage](https://img.shields.io/badge/function_coverage-91.9%25-lime?logo=freebsd&logoColor=white&style=plastic) ![freebsd-line-coverage](https://img.shields.io/badge/line_coverage-82.0%25-lime?logo=freebsd&logoColor=white&style=plastic)

``Macgonuts`` is an ``ARP/NDP`` swiss army knife to make ``MAC addresses`` going nuts on networks around!

It supports ``IPv4/ARP`` and ``IPv6/NDP``. It intends to bring you all in a shell. Anything related to
spoof `layer-2` addresses can be done elegantly with a single f_cking nice ``non-scripted`` tool, a
badass executable without clumsy zillions of dependencies. Suckless is the key here, but simple in a
*non-hollow-claimed-simple* is what we try to deliver here.

Currently, ``Macgonuts`` is compatible with ``Linux`` and ``FreeBSD`` platforms.

Still, if you want to do spoof from your own code, you can use basic stuff from ``Macgonuts`` as a
``C library`` or ``Go``, ``Python`` bind as well.

You should take your first steps [here](doc/BUILD.md) and so
buckle up and quickly mastering all the tool [here](doc/MANUAL.md).

I hope you like it, enjoy!

---

**Bear in mind**: Use this software at your own responsibility and risk. I am not responsible for any misuse of it,
including some kind of damage, data loss etc. Sniffing network, eavesdropping people's communication without them
knowing is wrong and a crime. Do not be a jerk, respect people rights. This tool was written with the intention of
being a support tool to test and promote security on networks through pentesting stuff, ethical hacking and also a
practice tool for computer networking courses besides a tool for pentest or red teams. You should use this tool
only into well controlled environments. If you will run ``Macgonuts`` on public networks, be sure of warning network
users of your actions before. Also be sure of loading your ``ethics.ko`` module before any network hacking action.
Finally, this software is provided with no warranty.

Again, ``Macgonuts`` is an ``ARP/NDP`` swiss army knife with batteries included but ethics you need to bring it
from home. :wink:

Remember to be ethical when using it. Macgonuts is a tool designed to ethical hacking, pentests and
red teams. *Once it stated, when using this tool you are assuming that any damage, data loss or even
law infringements that some wrong action taken by you could cause is of your entire responsibility*.

**Sponsoring**:  I have not been running this project for profit. It is only a thing that I do at my spare time. It is a
weekend project. I try to evolve it according to necessities I have been facing up during my information security
professional career. If you liked it or it is being useful to you somehow and you really want to contribute
with money, try to redirect it to a local charity institution, an ONG of your choice or even your own community.
You can also do [pull requests](https://github.com/rafael-santiago/macgonuts/pulls) proposing improvements.
Do some [bug report](https://github.com/rafael-santiago/macgonuts/issues) if a bug is annoying you. Maybe you should
also instruct people about network security issues by using this software showing them ways of being protected against
the attacks proposed here. Use it as a classroom lab tool, too. Well, spread your knowledge! Thank you!

**Obvious but always good to remember**: all opinions expressed here are my own and not the views of my employers.
