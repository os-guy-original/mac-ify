# glibc / Linux-side ground truth

The Linux side of every translation table. Fetched from the **installed
glibc 2.44** and the Linux kernel headers on the build machine, plus
glibc source (bminor mirror, master) for behavior that headers don't
show. Cite these instead of memory when touching translation code.

## Files

| File | Source | What it settles |
|---|---|---|
| `termios.h`, `termios-c_{iflag,oflag,cflag,lflag}.h`, `termios-c_cc.h`, `termios-struct.h` | glibc 2.44 `/usr/include/bits/` | Linux user-space flag values, NCCS=32, struct termios (c_line + union ispeed/ospeed) |
| `termios-baud.h` | glibc 2.44 | **Bxxx constants are literal rates since 2.42** ("sane speed_t"): B57600=57600U, B115200=115200U… |
| `kernel-asm-generic-termbits.h` | Linux `asm-generic/termbits.h` | Kernel ABI: CBAUD=0x100f, CBAUDEX=0x1000, BOTHER=0x1000, B57600=0x1001…B4000000=0x100f, CIBAUD<<IBSHIFT |
| `kernel-asm-generic-termios.h`, `kernel-linux-termios.h` | Linux uapi | Kernel struct termios/termios2/winsize definitions |
| `glibc-2.44-src/speed.c`, `linux-speed.c` | glibc source | cfget*/cfset* store literal values; `___speed_to_cbaud`/`___cbaud_to_speed` mapping tables (code↔rate); BOTHER for arbitrary rates |
| `glibc-2.44-src/tcsetattr.c`, `tcgetattr.c` | glibc source | tcsetattr→termios2 ioctl (TCSETS2), `___termios2_canonicalize_speeds` recomputes CBAUD from c_ispeed/c_ospeed |
| `glibc-2.44-src/cfsetspeed.c`, `linux-cfsetspeed.c` | glibc source | cfsetspeed = cfsetispeed+cfsetospeed passthrough |

## Why this matters (glibc 2.42 speed_t rework)

Pre-2.42, glibc's user-visible `B57600` was the *kernel code* 0x1001,
`cfgetospeed()` returned `c_cflag & CBAUD`, and `cfset*` wrote its
argument straight into CBAUD. Since the 2.42 "sane speed_t" rework
(cfsetspeed arbitrary-speeds commit de730d3d2d91, June 2025), glibc
stores **literal bit rates** and converts to kernel codes inside
tcsetattr/tcgetattr. Translation tables written against either
convention alone are wrong for the other generation — see
`shim/io/file.c` speed translation for the dual-convention handling.
