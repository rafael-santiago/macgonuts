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
    - [The developer's build](#developers-build)
    - [Installing the command line](#installing-the-command-line)

# Getting newest macgonuts source code revision

The easiest way is as follows:

```
you@somewhere-over-the-rainbow:~# git clone https://github.com/rafael-santiago/macgonuts --recursive
you@somewhere-over-the-rainbow:~# _
```

[``Back``](#topics)

# Build

``Macgonuts`` is a tool that has some points of ``suckless`` as its philosophy, so it tries to do
more possible without making you bloat your system with tons of 3rd party stuff that certainly has
untracked bugs by us. If it is impossible to have a system without bugs better to stick with your
own bugs and getting (less possible) in touch with bugs from other people. Thus, all you need to
build ``Macgonuts`` is:

- ``GCC`` or ``Clang``.
- ``libc`` (Harrrrrrd of having it on unixes, huh?).
- ``Pthread`` libraries well installed in your system.
- ``Hefesto`` (my build system of choice for this tool and if you want to contribute to ``Macgonuts`` you should install it).
- ``Make`` tool (if you are intending to run poor man's build only to get your macgonuts binaries to do your own stuff).

Any other dependency we ship it as sub-modules and build it during build but DO NOT polute your system
with nothing. It is used into ``src/libs`` folder of your copy. If you delete your copy, all will gone
with this deletion, clean.

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

Well, poor man's build is only to produce libraries and the command line tool. Due to it if you are adding new
features to macgonuts to open a pull request, better to run the developer's build based on Hefesto because it
will run tests, find for memory leak and stuff. Poor man's build does not run any test nor do any profile.

Having ``make`` tool well installed in your system, move to ``src`` toplevel subdirectory and:

```
you@somewhere-over-the-rainbow:~# cd macgonuts/src
you@somewhere-over-the-rainbow:~/macgonuts/src# make
```

If you are looking for the dynamic or static libraries, it will be built into ``lib`` toplevel directory.
If you are looking for the command line tool, it will be built into ``bin`` toplevel directory.

[``Back``](#topics)

## The developer's build

``Macgonuts`` is built with the idea that any source code hosted into ``src`` toplevel subdirectory is
used for codes into more specilized subdirectories into ``src``. Until now the only more specialized
subdirectory is ``src/cmd``. This ``cmd`` subdirectory stands for the ``macgonut's`` command line tool.

Codes directly put into ``src`` compound static libraries ``libmacgonuts.a`` and ``libmacgonutssock.a``.
The ``libmacgonutssock.a`` is a special case where all codes related to socket (into native implementations
``macgonuts_socket.o`` and ``macgonuts_socket_common.o`` are put together into a separated ar file, this
is done in order to make easy to test some communication parts).

Any specific code for some platform is hosted into a subdirectory with the name of the platform, so,
``src/linux/...`` gathers any specific implementation of stuff for Linux, for example.

Since ``macgonuts`` is a unix tool any code into ``src/unix`` is about ``POSIX`` compliant codes.

The directory ``src/build`` is where some conveniences for build tasks are written, I do not think that
you will need to deal with it. The build is done in a way that once put the source code in the exact
place of src tree, it will be compiled and built into the exact build artifact that the changed src tree
part is about.

So that is it! If you want to add new stuff for command line, your code must be hosted into ``src/cmd``.
If you want to add new stuff to macgonuts static library, this new code must be put into ``src``.

However, professional programmers test what they did before shipping. So, any "subpart" has its own
``test`` subdirectory that is where you need to write your tests. The tests are separated by translation units
of the part being tested named in the following scheme: ``<translation_unit_name>_tests.h`` and 
``<translation_unit_name>_tests.c``. So, if you created a new header and translation unit (``new_proto_conv.h`` and
``new_proto_conv.c``) their tests must map to ``test/new_proto_conv_tests.h`` and ``test/new_proto_conv_tests.c``.
If you just added a new function to some previous existent module, you only need to update the test files
by adding the test prototype and the test definition of the new stuff you added. Tests are called into every
``main.c`` present in each ``test`` subdirectory that you find. Try to keep a logical order of running. By running
the less dependent (basic stuff) before the more dependent, it will isolate the problem ``asap`` by giving us the
clue where is the exact bug.

For tests I have been using another library of mine called [cutest](https://github.com/rafael-santiago/cutest).

Tests are ran by default, so you will not face the risk of committing without locally testing your stuff to see
that it is now remotely broken, ;)

Well, knowing it and being into the toplevel ``src`` subdirectory, all you should do to build ``macgonuts``
with ``Hefesto`` is:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto
```

Libraries will be built into ``../lib`` and binaries into ``../bin``.

[``Back``](#topics)

## Installing the command line

Having ``Hefesto`` well installed all you need is move to ``src`` toplevel subdirectory and run the following:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --install
```

Unstalling is similar:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --uninstall
```

[``Back``](#topics)
