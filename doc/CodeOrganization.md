# Code organization

**Abstract**: This document aims to inform how ``Macgonuts`` code follows organized,
besides some project and design decisions.

## Topics

- [The repo layout](#repo-layout)
- [Code coverage parameters](#code-coverage-parameters)
    - [How to avoid breaking coverage build?](#how-to-avoid-breaking-coverage-build)
    - [Coverage measures updating](#coverage-measures-updating)
- [Design decision about libc and OS includes](#design-decision-about-libc-and-os-includes)
- [How does versioning work on `macgonuts`?](#how-does-versioning-work-on-macgonuts)
    - [But why taking this so unpopular decision?](#but-why-taking-this-so-unpopular-decision)
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
|   |   +-- ...
|   +-- binds/
|   |   +-- ...
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
| **Directory level**    |          **Here goes**                              |
|:----------------------:|:---------------------------------------------------:|
|     toplevel           | Main configuration and information files            |
|   ``.github``          | Files related to github configuration               |
| ``.github/workspaces`` | Configuration of ``CI`` stuff                       |
|  ``doc``               | More specific documentation                         |
|  ``doc/man1``          | ``Macgonuts`` tool man page                         |
| ``etc``                | Miscellaneous stuff                                 |
| ``src``                | Main source (library)                               |
| ``src/binds``          | ``Macgonuts`` binds for other programming languages |
| ``src/build``          | Build conveniences stuff                            |
| ``src/cmd``            | Command line tool source code                       |
| ``src/cmd/hooks``      | Source code for task hooks of ``CLI`` tool          |
| ``src/cmd/test``       | Tests for the ``CLI`` tool                          |
| ``src/freebsd``        | ``FreeBSD`` native code of main source (library)    |
| ``src/libs``           | All dependencies used by ``Macgonuts`` code         |
| ``src/linux``          | ``Linux`` native code of main source (library)      |
| ``src/test``           | Tests for the library                               |
| ``src/unix``           | Common ``UNIX-like`` codes                          |

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
is able to detect that ``README.md`` has changed and it pushes these changes through an automated commit.

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

## How does versioning work on `macgonuts`?

<p align="center">
<img src="https://github.com/rafael-santiago/macgonuts/blob/main/etc/warning_unpopular_content.png" title="I love The Cramps, don't you?"
     alt="I love The Cramps, don't you?" width="320" /><br>
<img src="https://github.com/rafael-santiago/macgonuts/blob/main/etc/the_surprise_in_terror_1790.png" title="The Surprise in Terror (1790) by Joseph Ducreux (Public Domain)"
     alt="The Surprise in Terror (1790) by Joseph Ducreux (Public Domain)" width="320" />
<img src="https://github.com/rafael-santiago/macgonuts/blob/main/etc/le_discret_1791.png" title="Le Discret (1791) by Joseph Ducreux (Public Domain)"
     alt="The Surprise in Terror (1790) by Joseph Ducreux (Public Domain)" width="320" />
</p>

After thinking about endless months! I have decided to use an arcane and unusual (really) way of versioning computer
programs. It is so unusual that deserves a whole paragraph and in all caps (sorry).

HERE WE ARE USING INTEGERS AND ALWAYS COUNTING IN ASCENDENT ORDER, STARTING FROM THE NUMBER ONE.

Very, very unusual. So unusual that it needs to be more well explained. One more paragraph (no caps, I promise)...

So, the first version is `v1`, the next `v2` and after `v3`. Now it is up to you...

I tried avoid reinventing math axioms, better to stick with the previous, they work and they are amazing.

Now, in other words: arabic numbers going in ascendent order starting from one, prefixed with `v` (suggesting "version").

With this decision, unfortunately, here you will not find ridiculous names (besides `macgonuts`)... You know,
things like:

- `vCucumber-from-space-and-beyond`
- `vProjeto-pangaio`
- `vMais-um`
- `v_i`
- `v_ii`
- `v_ii.i`
- `vVamos-ver-se-agora-vai-1.2.3.4.5.6`
- `v3.14+E10`
- `vNome-de-pessoa-aleatório-e-bem-bobo`
- `vZumbi-pindoba`
- `vMais-um-jabuti-que-subiu-na-arvore`
- `vNomeDeAnimalFofuxim`
- `vHlp_whr_r_th_vgls`

etc...

Instead, here you will find:

- `v1`

and possibly:

- `v2`
- `v3`
- `v4`

- and counting... if we have new ideas or bugs to fix... Because here subjectless "new" versions are totally pointless and
unable to be released.

[``Back``](#topics)

### But why taking this so unpopular decision?

`Macgonuts` is the only ridiculous name that you will find here, there is no place for another one.
It is a thing like `Highlanders`. We are predatory about it, period.

[``Back``](#topics)
