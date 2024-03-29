# Build instructions

**Abstract**: ``Macgonuts`` main build is based on another tool of mine called [Hefesto](https://github.com/rafael-santiago/hefesto).
If you want to contribute to ``macgnonuts`` you need to know details about it. If you are only seeking to get a
fresh ``macgonuts`` binary to get your stuff done, you can give ``the low-cost build`` a try. It uses simply
``Makefiles``. So, get your build instructions destiny below.

## Topics

- [Getting newest macgonuts source code revision](#getting-newest-macgonuts-source-code-revision)
- [Build](#build)
    - [Installing Hefesto](#installing-hefesto)
    - [The low-cost build](#the-low-cost-build)
    - [The developer's build](#developers-build)
        - [Extracting code coverage](#extracting-code-coverage)
        - [List of all build options](#list-of-all-build-options)
    - [Installing the command line tool](#installing-the-command-line-tool)
    - [Building the debian package](#building-the-debian-package)
    - [Building the binds](#building-the-binds)
        - [pybind](#pybind)
        - [gobind](#gobind)

## Getting newest macgonuts source code revision

The easiest way is as follows:

```
you@somewhere-over-the-rainbow:~# git clone https://github.com/rafael-santiago/macgonuts --recursive
you@somewhere-over-the-rainbow:~# _
```

[``Back``](#topics)

## Build

``Macgonuts`` is a tool that has some points of ``suckless`` as its philosophy, so it tries to do
more possible without making you bloat your system with tons of ``3rd party`` stuff that certainly has
untracked bugs by us. If it is impossible to write a program without bugs, it is better to stick with your
own bugs and getting (less possible) in touch with bugs from other people. Thus, all you need to
build ``Macgonuts`` is:

- ``GCC`` or ``Clang``.
- ``libc`` (Harrrrrrd of having it on unixes, huh?).
- ``Pthread`` libraries well installed in your system.
- ``Hefesto`` (my build system of choice for this tool and if you want to contribute to ``Macgonuts`` you should install it).
- ``GNUMake`` tool (if you are intending to run low-cost build only to get your ``macgonuts`` binaries to do your own stuff).

Any other dependency we ship it as sub-modules and build it during build but ``DO NOT`` polute your system
with nothing. It is used into ``src/libs`` folder of your copy. If you delete your copy, all will gone
with this deletion, simple, self contained and clean. Tideness is everything! :wink:

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

Now you need to install some conveniences for code coverage extractions, so you need to clone `Helios`
and install `lcov-generator`:

```
you@somewhere-over-the-rainbow:~# git clone https://github.com/rafael-santiago/helios
you@somewhere-over-the-rainbow:~# cd helios
you@somewhere-over-the-rainbow:~/helios# hefesto --install=lcov-generator
you@somewhere-over-the-rainbow:~/helios# cd ..
you@somewhere-over-the-rainbow:~# rm -rf helios
```

You can also run the script ``get-hefesto.sh`` into ``src`` folder of ``Macgonuts``.

[``Back``](#topics)

## The low-cost build

Well, ``low-cost build`` is only to produce libraries and the command line tool. Due to it if you are adding new
features to macgonuts by opening a pull request, better to run the developer's build based on ``Hefesto`` because it
will run tests, search for memory leak and stuff. ``Low-cost build does not run any test nor do any profile``.

Having ``GNU make`` tool well installed in your system, move to ``src`` toplevel subdirectory and execute `make`:

```
you@somewhere-over-the-rainbow:~# cd macgonuts/src
you@somewhere-over-the-rainbow:~/macgonuts/src# make
```

If you are looking for the dynamic or static libraries, it will be built into ``lib`` toplevel directory.
If you are looking for the command line tool, it will be built into ``bin`` toplevel directory.

In order to install the build artifacts, run:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# make install
```

Uninstalling:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# make uninstall
```

[``Back``](#topics)

## The developer's build

``Macgonuts`` is built with the idea that any source code hosted into ``src`` toplevel subdirectory is
used by codes gathered into more specilized subdirectories of ``src`` toplevel. Until now the only more specialized
subdirectory is ``src/cmd``. This ``cmd`` subdirectory stands for the ``macgonuts'`` command line tool.

Codes directly hosted into ``src`` compound the static libraries ``libmacgonuts.a`` and ``libmacgonutssock.a``.
The ``libmacgonutssock.a`` is a special case where all codes related to socket (into native implementations
``macgonuts_socket.o`` and ``macgonuts_socket_common.o`` are put together into a separated ``ar`` file, this
is done in order to make easy to test some communication parts).

Any specific code for some platform is hosted into a subdirectory with the name of the platform, so,
``src/linux/...`` gathers any specific implementation of stuff for ``Linux``, for example.

Since ``macgonuts`` is a ``unix tool`` any code into ``src/unix`` is about ``POSIX`` compliant codes.

The directory ``src/build`` is where some conveniences for build tasks are written, I do not think that
you will need to deal with it. The build is done in a way that once put the source code in the exact
place of the src tree, it will be compiled and built into the exact build artifact that the changed src tree
part is about.

So that is it! If you want to add new stuff for command line, your code must be hosted into ``src/cmd``.
If you want to add new stuff to ``macgonuts`` static library, this new code must be put into ``src``.

However, professional programmers test what they did before shipping, right? So, any "subpart" has its own
``test`` subdirectory that is where you need to write your tests. The tests are separated by translation units
of the part being tested. Being it named in the following scheme: ``<translation_unit_name>_tests.h`` and
``<translation_unit_name>_tests.c``. So, if you created a new header and translation unit (``new_proto_conv.h`` and
``new_proto_conv.c``) their tests must map to ``test/new_proto_conv_tests.h`` and ``test/new_proto_conv_tests.c``.
If you just added a new function to some previous existent module, you only need to update the test files
by adding the test prototype and the test definition of the new stuff you added. Tests are called into every
``main.c``. It is present in each ``test`` subdirectory that you find. Try to keep a logical order of running.
By running the less dependent (basic stuff) before the more dependent, it will isolate the problem ``asap`` by
giving us the clue where the introduced bug exactly is.

For tests I have been using another library of mine called [cutest](https://github.com/rafael-santiago/cutest).

Tests are ran by default, so you will not face the risk of committing without locally testing your stuff to see
that it is now remotely broken, :wink:

Well, knowing it and being into the toplevel ``src`` subdirectory, all you should do when building ``macgonuts``
with ``Hefesto`` is:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto
```

Libraries will be built into ``../lib`` and binaries into ``../bin``. Tests will ran automatically, if you have been
doing a good job you will not fear them and, I am pretty sure that you will like to watch them running every single time
remembering you that your code is actually working and that ``TDD`` matters. :raised_hands:

[``Back``](#topics)

### Extracting code coverage

``Macgonuts`` build gives support for code coverage extraction, it support ``gcov`` or ``llvm-cov``. You also need to
have ``lcov`` well-installed more on that [here](https://github.com/linux-test-project/lcov).

By using ``Hefesto`` we can easily extract ``Macgonuts``' code coverage by invoking ``Hefesto`` as follows:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --coverage
```

By default the report will be generated under ``src/reports`` directory. If you want to specify a directory to generate
the reports you can pass the option ``--genhtml-outpath=<directory path>`` option:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --coverage \
> --genhtml-outpath=/mnt/tdd/rocks
```

By design we are only extracting code coverage from ``libmacgnuts`` (the main project under ``src``).
The ``cmd-tool`` is pretty hard for automate tests since it would involve run all attacks that this tool
implements in form of commands (a.k.a tasks) from the `CI`. Sincerely, it would be not
easy to do from a rather ``restricted-docker-velotrol-like`` [sic] environment. So, *C'est la vie!*

> - Wait. What does *"velotrol"* is?!

Well, a image will make you understand my point much better, [look](https://duckduckgo.com/?q=velotrol&t=h_&iax=images&ia=images)! :rofl:

[``Back``](#topics)

### List of all build options

Take a look at **Table 1** to know all build options supported by the ``Hefesto`` based build.

**Table 1** : All relevant ``Macgonuts`` build options.
| **Option**          | **Type**  |                               **Description**                                       |
|:-------------------:|:---------:|:-----------------------------------------------------------------------------------:|
| ``--includes``      |   list    | Specifies additional include directories                                            |
| ``--cflags``        |   list    | Specifies additional compilation flags                                              |
| ``--libraries``     |   list    | Specifies additional library directories                                            |
| ``--ldflags``       |   list    | Specifies additional linker flags                                                   |
| ``--bin-output-dir``|   value   | Specifies the binary artifact target directory                                      |
| ``--obj-output-dir``|   value   | Specifies the object files target directory                                         |
| ``--install``       |   flag    | Runs installing build task                                                          |
| ``--uninstall``     |   flag    | Runs uninstalling build task                                                        |
| ``--coverage``      |   flag    | Runs coverage build task                                                            |
|``--genhtml-outpath``|   value   | Specifies a file path for the ``LCOV`` coverage report                              |
| ``--toolset``       |   value   | Specifies the name of wanted compiler, can being ``gcc`` or ``clang``               |
| ``--debian-pkg``    |   flag    | Runs the debian packaging build task                                                |
| ``--with-pybind``   |   flag    | Includes ``Python``'s bind compilation in the main build task                       |
| ``--with-gobind``   |   flag    | Includes ``Golang``'s bind compilation in the main build task                       |

[``Back``](#topics)

## Installing the command line tool

Having ``Hefesto`` well installed all you need is move to ``src`` toplevel subdirectory and run the following:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --install
```

Uninstalling is similar:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --uninstall
```

[``Back``](#topics)

## Building the debian package

The ``debian`` package can be built through the ``developer's`` build or through the ``low-cost`` build.
The ``package`` is created in the toplevel ``deb`` sub-directory.

By using the ``developer's`` build and being into ``src`` sub-directory, you need to invoke ``Hefesto`` as follows:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --debian-pkg
```

By using the ``low-cost`` build and being into ``src`` sub-directory, you need to run ``make`` as follows:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# make deb
```

[``Back``](#topics)

## Building the binds

In this part you can find instructions about how to build the available ``macgonuts`` binds.

[``Back``](#topics)

### pybind

The ``Macgonuts`` ``Python`` bind depends on ``cython``, so in order to install it you can use the following:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# pip install cython
```

Done! Now is time to actually build ``macgonuts_pybind``.

By using the ``developer's`` build and being into ``src`` sub-directory, you need to invoke ``Hefesto`` passing
the option ``--with-pybind``:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --with-pybind
```

When using the ``low-cost`` build you also need to be into ``src`` sub-directory and call ``make`` defining the
build parameter ``with-pybind``:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# make with-pybind=yes
```

The ``python`` bind artifacts will be built into ``src/binds/py``.

[``Back``](#topics)

### gobind

In order to build ``Macgonuts`` ``Golang`` bind by using the ``developer's`` build you need to invoke ``Hefesto`` passing
the option ``--with-gobind`` (supposing you are into ``src`` sub-directory):

```
you@somewhere-over-the-rainbow:~/macgonuts/src# hefesto --with-gobind
```

If you want to use ``low-cost`` build instead, also being into ``src`` sub-directory, call ``make`` defining the build
parameter ``with-gobind``:

```
you@somewhere-over-the-rainbow:~/macgonuts/src# make with-gobind=yes
```
