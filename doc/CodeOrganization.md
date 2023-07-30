# Code organization

**Abstract**: This document aims to inform how ``Macgonuts`` code follows organized,
besides some project and design decisions.

## Topics

- [The repo layout](#repo-layout)
- [Code coverage parameters](#code-coverage-parameters)
    - [How to avoid breaking coverage build?](#how-to-avoid-breaking-coverage-build)
    - [Coverage measures updating](#coverage-measures-updating)
- [Design decision about libc and OS includes](#design-decision-about-libc-and-os-includes)

## The repo layout

This is the current repo layout:

```
.
+-- CODE_OF_CONDUCT-PT_BR.md
+-- CODE_OF_CONDUCT.md
+-- LICENSE
+-- README.md
+-- .github/
|   +-- workflows/
|       +-- forge-specs.yml
+-- doc/
|   +-- BUILD.md
|   +-- CodeOrganization.md
|   +-- CodingStyle.md
|   +-- MANUAL.md
|   +-- man1/
|       +-- macogonuts.1
+-- etc/
|   +-- hoax
|   +-- oui
|   +-- ...
+-- src/
|   +-- Forgefile.hsl
|   +-- ...
|   +-- build/
|       +-- toolsets.hsl
|   +-- cmd/
|       +-- Forgefile.hsl
|       +-- hooks/
|           +-- ...
|       +-- test/
|           +-- Forgefile.hsl
|           +-- ...
|       +-- ...
|   +-- freebsd/
|       +-- ...
|   +-- libs/
|       +-- ...
|   +-- linux/
|       +-- ...
|   +-- test/
|       +-- Forgefile.hsl
|       +-- ...
|   +-- unix/
|       +-- ...
+-- ...
```

In order to know more details about each directory level take a look at **Table 1**.

**Table 1**: Directory levels overview.
| **Directory level**    |          **Here goes**                           |
|:----------------------:|:------------------------------------------------:|
|     toplevel           | Main configuration and information files         |
|   ``.github``          | Files related to github configuration            |
| ``.github/workspaces`` | Configuration of ``CI`` stuff                    |
|  ``doc``               | More specific documentation                      |
|  ``doc/man1``          | ``Macgonuts`` tool man page                      |
| ``etc``                | Miscellaneous stuff                              |
| ``src``                | Main source (library)                            |
| ``src/build``          | Build conveniences stuff                         |
| ``src/cmd``            | Command line tool source code                    |
| ``src/cmd/hooks``      | Source code for task hooks of ``CLI`` tool       |
| ``src/cmd/test``       | Tests for the ``CLI`` tool                       |
| ``src/freebsd``        | ``FreeBSD`` native code of main source (library) |
| ``src/libs``           | All dependencies used by ``Macgonuts`` code      |
| ``src/linux``          | ``Linux`` native code of main source (library)   |
| ``src/test``           | Tests for the library                            |
| ``src/unix``           | Common ``UNIX-like`` codes                       |

[``Back``](#topics)

## Code coverage parameters

Code coverage here it is not a fancy measure only to plot meanginless charts. In fact,
here you will not find any chart (thanks gosh!); here code coverage is destined to
developers and as pragmatic developers we like objective stuff that help us to solve
the problem quickly, in other words:

- it is good.
- it is acceptable.
- it is bad (shame on us, let's get better), btw the build is broken, fix it before continuing.

and, period. No fiddle-faddle. **Table 2** summarizes what exactly is ``good``, ``acceptable`` and ``shame on us``.

**Table 2**: Our adopted coverage measure range.
| **Coverage range (line/function)**|                  **Description**                     |
|:---------------------------------:|:----------------------------------------------------:|
|       ``>= 90%``                  |               it is considered high, good            |
|       ``>= 75% && <= 90%``        |               it is considered medium, acceptable    |
|       ``< 75%``                   |               it is considered low, bad, shame on us |

*Coverage build breaks when some low coverage is detected*. By default ``CI`` runs coverage build.

[``Back``](#topics)

### How to avoid breaking coverage build?

Well, if you have added new codes to ``Macgonuts`` you need to exercize this new code with some testing,
no small talk. The ``CI`` produces as artifact the ``LCOV`` report from the part of ``Macgonuts`` that
is watched (the library). With this report you can *clearly see (as *C* code)* how uncovered parts are
needing to be more exercized during tests to make ``CI`` pass again.

[``Back``](#topics)

### Coverage measures updating

At each ``CI`` execution the coverage build runs on ``Linux`` based build step. The coverage build is
able to update the coverage measures indicated in the toplevel ``README.md`` file. Likewise, the ``CI`` part
is able to detected that ``README.md`` has changed and it pushes these changes through an automated commit.

Unfortunately, until now, the ``FreeBSD CI``'s part is not executing the coverage build, because it is
just about a workaround done from a ``VM``.

When you are in a coverage increasement task you will need to run the coverage build by yourself in your own
development environment, and after hitting good coverage indexes all you need to do is committing your
changes what btw will include the ``README.md`` coverage badges updated.

[``Back``](#topics)

## Design decision about libc and OS includes

Any include related to the ``operating system`` and also ``libc`` should be done from within ``macgonuts_types.h``.
Excluding platform dependent code that is shipped inside the directory named with the platform name, in those
implementation and headers files is okay including ``libc`` and the ``OS`` headers.

By doing it we are able to make easier to get all depedency for certain base stuff without inflating the ``macgonuts``
code space with so repetitive include statements. Thus, we can include what we need to get the job done ASAP and
focusing on implementing that exact part and, period.

[``Back``](#topics)
