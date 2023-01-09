# Build instructions

**Abstract**: ``Macgonuts`` main build is based on another tool of mine called [Hefesto](https://github.com/rafael-santiago/hefesto).
If you want to contribute to ``macgnonuts`` you need to know details about it. If you are only seeking to get a
freshly macgonuts binary to get your stuff done, you can give the poor man's build a try that uses simply ``Makefiles``.
Get your build instructions destiny below.

# Topics

- [Getting newest macgonuts source code revision](#getting-newest-macgonuts-source-code-revision)
- [Build](#build)
    - [Installing Hefesto](#installing-hefesto)
    - [The poor man's build](#the-poor-mans-build)

# Getting newest macgonuts source code revision

The easiest way is as follows:

```
you@somewhere-over-the-rainbow:~# git clone https://github.com/rafael-santiago/macgonuts --recursive
you@somewhere-over-the-rainbow:~# _
```

[``Back``](#topics)

# Build

``Macgonuts`` is a tool that has some points of ``suckless`` as its philosophy, so it tries to do
more possible without make you bloat your system with tools of 3rd party stuff that certainly has
untracked bugs by us. If it is impossible to have a system without bugs better to stick with your
own bugs... All you need to build ``Macgonuts`` is:

- ``GCC`` or ``Clang``.
- ``libc`` (Harrrrrrd of having it, hahahahaha).
- ``Pthread`` libraries well installed in your system.
- ``Hefesto`` (my build system of choice for this tool and if you want to contribute to ``Macgonuts`` you should install it).
- ``Make`` tool (if you are intending to run poor man's build).

Any other dependency we ship it as sub-modules and build it during build but DO NOT polute your system
with nothing. It is used into ``src/libs`` folder of your copy.

## Installing Hefesto

You need to do the following:

```
you@somewhere-over-the-rainbow:~# git clone https://github.com/rafael-santiago/hefesto --recursive
you@somewhere-over-the-rainbow:~# cd hefesto/src
you@somewhere-over-the-rainbow:~/hefesto/src# ./build.sh
(...)
you@somewhere-over-the-rainbow:~/hefesto/src# logout
(redo login and you done)
```

You can also run the script ``get-hefesto.sh`` into ``src`` folder of ``Macgonuts``.

[``Back``](#topics)

## The poor man's build

[``Back``](#topics)

