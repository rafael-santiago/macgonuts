![Ancient Greek Pegasus Coin / Public Domain](https://github.com/rafael-santiago/macgonuts/blob/main/etc/pegasus_coin.png "Ancient Greek Pegasus Coin / Public Domain")

# Quick coding style guide

**Excuses..err, Abstract**: Coding is a kind of craft that involves many cultural and idiomatic stuff. Due to it,
well as in many other segments, ``the Truth`` is such a ``big, biiiig winged unicorn``... Anyway, the following text
seeks to describe ``objectively`` the main features of ``my current Unicorn``.


# Topics

- [Basic formatting](#basic-formatting)
- [Header files](#header-files)
- [Implementation files](#implementation-files)
- [Naming things](#naming-things)
- [If..Else blocks](#ifelse-blocks)
- [While blocks](#while-blocks)
- [Do..While blocks](#dowhile-blocks)
- [Functions](#functions)
- [Gotos](#gotos)
- [Comments and documentation](#comments-and-documentation)
- [The definition of done](#the-definition-of-done)


Have you found some unclear point here? Help me to improve it by opening a related [issue](https://github.com/rafael-santiago/macgonuts/issues) and, thank you!

## Basic formatting

1. Here we are replacing ``tabs`` with ``spaces`` and a tab is equals to ``4 spaces`` (some text editors understands 4
as 8 spaces, maybe due to a different base, the Truth...).

2. An indentation level is given by ``one tab``.

3. Control blocks have to be always embraced with ``{ ... }``.

4. Yes, ``80`` columns is a really short limit, try not to exceed ``120``!

## Header files

1. Headers files have to start with a copyright disclaimer (that you can get from ``macgonuts_types.h``, for example).

2. Avoid ``#pragma once``, please. Use standard include guards. We do not want to force users to update
their toolchain just for building our stuff, this is tech facism... Really! Good software projects must
be ready to compile anywhere it should. Try to use the less possible because less is quicker and less
headache prone. New features are awesome but it is a cutting point in practice. For example [``Boojum``](https://github.com/rafael-santiago/boojum)
is ready to use ``C11 threading``, it is compiling in many environments but it is not linking! Due to ``libc``
inconsistences. Some OSes are using newest compiler versions but their library are still old. I am writing it in ``2023``!

3. Avoid implementing things directly into headers.

[``Back``](#topics)

## Implementation files

1. Implementation files have to start with a copyright disclaimer (that you can get from ``macgonuts_types.h``, for example).

2. Functions that are unused outside from the implementation file must be ``static``.

3. Even being ``static`` those functions must be prototyped at the beginning of the implementation file.

4. Give preference for listing the public one first in the implementation file. So the public ones goe at the top of
   the implementation file the static ones after the last public one implementation.

[``Back``](#topics)

## Naming things

1. Avoid prepend names with underscores (``________this_is_anti_pattern``).

2. Try to find the best balance between information and objectivity.

3. Be idiomatic to the knowledge field you are coding for, instead of coding for the design pattern book that you love.
   Here, the knowledge field is ``computer network``, ``network hacking``, ``ARP/NDP exploitation``, ``network spoofing``
   and so on.

4. ``snake_case`` is the generic naming convention of choice here.

[``Back``](#topics)

## If..Else blocks

This is the adopted style:

```c
    if (abc == def) {
        do_this(def, ghi);
    } else {
        do_that(ghi);
    }
```

[``Back``](#topics)

## While blocks

This is the adopted style:

```c
    while (!yours_not_equals) {
        reformat_this();
    }
```

[``Back``](#topics)

## Do..While blocks

This is the adopted style:

```c
    do {
        reformat_this();
    } while (!yours_not_equals);
```

[``Back``](#topics)

## Functions

This is the adopted style:

```c
int do_something(const int i_know_but_better_to_const, const char *buf, const size_t buf_size) {
    // All variables declared here, so you can plan before going.
    return whatever;
}
```

[``Back``](#topics)

## Gotos

Since ``C language`` does not feature a deferring or ``try..finally`` statements, here we use
``goto`` for accomplishing clean up necessities. With it you can conclude that here gotos only
jump forward and to the end of the function. Try to never use explicit gotos to jump backward.

```c
int do_messy_prologue(void) {
    ...
    if (err != EXIT_SUCCESS) {
        goto do_messy_prologue_epilogue;
    }
    ...
do_messy_prologue_epilogue:
    // Clean up all mess.
    return err;
}
```

[``Back``](#topics)

## Comments and documentation

Try not be a blasé programmer. Stop thinking you are a poet or a genius while coding or a zen haiku coder.
It does not exist. Sometimes you need to comment your stuff for other ones or even for you in the future.
Try to deliver pieces of engineering that would exist even many centuries after you gone, instead of
lousy book samples snippets that falls apart on a minimal poke.

Your code must stand up even without having you around. Less people needing you around to build your
stuff, more (good) engineering you are doing, more time you have to do different stuff instead of nursing
some sloppy source codes. You have a brain and a life do not waste them. Really!

When it is necessary to add a comment, try to use the following meaningful comment markers:

- ``INFO(Your name or nickname):`` You should use it for general information.
- ``WARN(Your name or nickname):`` You should use it for warning up something.
- ``FIXME(Your name or nickname):`` You have found a bug but do not know how to fix it, but your are still pointing it.
- ``BUG(Your name or nickname):`` This is really a bad bug. Help!
- ``TODO(Your name or nickname):`` A todo marker.

It is up to you to pick:

```c
// INFO(Rafael): This style,
```

```c
/* INFO(Rafael): or this one. */
```

However, consider ``MISRA-C`` points about ``// ... `` style one.

All new features must be documented by including its advantages and drawbacks. Always be fair with the users.

[``Back``](#topics)

## The definition of done

A new feature is considered done when:

1. It does what it must do.
2. It does not add mess, confusion or even unstability nor bugs in the previous stuff.
3. It ships what it promises in a simple (but not simpler) way. In other words, you have used Occam's razor principle on it.
4. It is being well tested.
5. It must not be tied up with some compiler or toolchain to work on. The opposite would be an example of lousy engineering,
   here. More concepts less dependencies.
6. The ``CI`` must be passing.
7. It is well documented.
8. The commit that adds this new feature to the upstream is descriptive.
   The commit should be direct but it must not be laconic/blasé/cryptic.
9. The commit message must use imperative form. Acting like you are giving commands to the version control system.
   So ``Giving commands to the version control system`` is wrong. ``Gives commands to the version control system`` still.
   ``Give commands to the version control system``. Do not be shy of being bossy with it! :wink:

[``Back``](#topics)
