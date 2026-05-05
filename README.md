# dtnc

Delay-tolerant netcat (dtnc) is a utility for [ION-DTN][ion]
reminiscent of OpenBSD netcat.
DTN does not have connections, so expect behavior closer to `nc -u`.

It is currently work in progress,
but the goal is to support nc options that are easily to translate
into a DTN setting,
and to support options specific to DTN.

## Requirements

* Meson
* ION 4.1.4
* <stdatomic.h>
* POSIX-like OS

## Setup

To build with ION, the build directory needs to be configured
to find ION's `.pc` file. E.g.,

```
meson setup --pkg-config-path /usr/local/lib/pkgconfig build
meson compile -C build
```

Install with:
```
meson install -C build
```
Uninstall with:
```
ninja uninstall -C build
```

[ion]: https://github.com/nasa-jpl/ION-DTN
