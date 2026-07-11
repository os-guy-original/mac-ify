# Translation Reference

This document describes what macify translates and how.

## 1. Syscall Numbers

macOS uses BSD syscall numbers (with 0x2000000 prefix for UNIX syscalls).
Linux uses different numbers. The loader patches `mov eax, <bsd_nr>` +
`syscall` instructions in the binary's __TEXT segment at load time.

### Fast Path (patched at load)

Syscalls with no argument translation are patched inline:
- The BSD syscall number in the `mov eax` immediate is replaced
  with the Linux equivalent
- The `syscall` instruction stays unchanged
- Zero runtime overhead

Example: `mov eax, 0x2000001` (macOS exit) becomes `mov eax, 0x3C`
(Linux exit_group), then `syscall` runs natively.

### Slow Path (UD2 + SIGILL handler)

Syscalls that need argument translation are patched to `UD2` (illegal
instruction). When executed, a SIGILL handler:
1. Reads the original BSD syscall number from nearby `mov eax`
2. Translates arguments (flags, structs, etc.)
3. Executes the Linux syscall
4. Returns the result

### Key Syscall Mappings

| macOS (BSD)          | Linux           | Notes                          |
|----------------------|-----------------|--------------------------------|
| 1 (exit)             | 231 (exit_group)|                                |
| 2 (fork)             | 57 (clone)      | Flags translated               |
| 3 (read)             | 0 (read)        | Same                           |
| 4 (write)            | 1 (write)       | Same                           |
| 5 (open)             | 2 (open)        | Flags translated               |
| 6 (close)            | 3 (close)       | Same                           |
| 73 (munmap)          | 11 (munmap)     | Same                           |
| 197 (mmap)           | 9 (mmap)        | Flags translated               |
| 202 (sysctl)         | N/A             | Stubbed                        |

## 2. Open Flags

macOS and Linux use different flag values for `open()`.

| macOS Flag         | Value | Linux Flag         | Value |
|--------------------|-------|--------------------|-------|
| O_RDONLY           | 0x0   | O_RDONLY           | 0x0   |
| O_WRONLY           | 0x1   | O_WRONLY           | 0x1   |
| O_RDWR             | 0x2   | O_RDWR             | 0x2   |
| O_CREAT            | 0x200 | O_CREAT            | 0x40  |
| O_EXCL             | 0x800 | O_EXCL             | 0x80  |
| O_TRUNC            | 0x400 | O_TRUNC            | 0x200 |
| O_APPEND           | 0x8   | O_APPEND           | 0x400 |
| O_NONBLOCK         | 0x4   | O_NONBLOCK         | 0x800 |
| O_SYNC             | 0x80  | O_SYNC             | 0x101000 |
| O_NOCTTY           | 0x10000 | O_NOCTTY         | 0x100 |
| O_DIRECTORY        | 0x100000 | O_DIRECTORY     | 0x10000 |
| O_NOFOLLOW         | 0x200000 | O_NOFOLLOW      | 0x20000 |
| O_CLOEXEC          | 0x1000000 | O_CLOEXEC       | 0x80000 |
| MAP_ANON           | 0x1000 | MAP_ANONYMOUS     | 0x20  |

Translation happens in `shim/io/flags.c`.

## 3. Signal Numbers

macOS and Linux diverge on signal numbers starting from SIGBUS.

| macOS Signal | macOS # | Linux Signal | Linux # |
|--------------|---------|--------------|---------|
| SIGHUP       | 1       | SIGHUP       | 1       |
| SIGINT       | 2       | SIGINT       | 2       |
| SIGQUIT      | 3       | SIGQUIT      | 3       |
| SIGILL       | 4       | SIGILL       | 4       |
| SIGTRAP      | 5       | SIGTRAP      | 5       |
| SIGFPE       | 8       | SIGFPE       | 8       |
| SIGKILL      | 9       | SIGKILL      | 9       |
| SIGBUS       | 10      | SIGBUS       | 7       |
| SIGSEGV      | 11      | SIGSEGV      | 11      |
| SIGSYS       | 12      | SIGSYS       | 31      |
| SIGPIPE      | 13      | SIGPIPE      | 13      |
| SIGALRM      | 14      | SIGALRM      | 14      |
| SIGTERM      | 15      | SIGTERM      | 15      |
| SIGURG       | 16      | SIGURG       | 23      |
| SIGSTOP      | 17      | SIGSTOP      | 19      |
| SIGTSTP      | 18      | SIGTSTP      | 20      |
| SIGCONT      | 19      | SIGCONT      | 18      |
| SIGCHLD      | 20      | SIGCHLD      | 17      |
| SIGUSR1      | 30      | SIGUSR1      | 10      |
| SIGUSR2      | 31      | SIGUSR2      | 12      |

Translation happens in `shim/signal/sigmask.c`.

## 4. struct stat

macOS and Linux have completely different `struct stat` layouts.

### macOS struct stat (144 bytes)

```
Offset  Field          Size
0       st_dev         4
4       st_mode        2
6       st_nlink       2
8       st_ino         8
16      st_uid         4
20      st_gid         4
24      st_rdev        4
28      (padding)      4
32      st_atim        16 (timespec)
48      st_mtim        16
64      st_ctim        16
80      st_birthtim    16
96      st_size        8
104     st_blocks      8
112     st_blksize     4
116     st_flags       4
120     st_gen         4
124     st_lspare      4
128     st_qspare      16
```

### Linux struct stat (144 bytes)

```
Offset  Field          Size
0       st_dev         8
8       st_ino         8
16      st_nlink       8
24      st_mode        4
28      st_uid         4
32      st_gid         4
36      __pad          4
40      st_rdev        8
48      st_size        8
56      st_blksize     8
64      st_blocks      8
72      st_atim        16
88      st_mtim        16
104     st_ctim        16
```

Translation happens in `shim/io/file.c` (`translate_stat`).

## 5. struct termios

macOS has 20 c_cc entries + speed fields (60 bytes).
Linux has 19 c_cc entries + c_line (36 bytes).

Translation happens in `shim/io/file.c` (`tcgetattr`/`tcsetattr`).

## 6. struct dirent

macOS dirent has d_seekoff and d_namlen fields that Linux lacks.

Translation happens in `shim/io/dirent.c`.

## 7. struct glob_t

macOS glob_t is 56 bytes. Linux glob_t is 64 bytes (extra gl_errfunc).

Translation happens in `shim/io/glob.c`.

## 8. Filesystem Path Translation

macOS binaries see `/` as the prefix root (`~/.macify/`).

| macOS Path          | Translated To              | Notes                    |
|---------------------|----------------------------|--------------------------|
| /bin/               | ~/.macify/bin/             | macOS binaries           |
| /usr/bin/           | ~/.macify/usr/bin/         | macOS binaries           |
| /usr/lib/           | ~/.macify/usr/lib/         | macOS libraries          |
| /usr/local/         | ~/.macify/usr/local/       | Homebrew packages        |
| /etc/               | ~/.macify/etc/             | macOS config files       |
| /var/               | ~/.macify/var/             | Variable data            |
| /Library/           | ~/.macify/Library/         | macOS system Library     |
| /System/Library/    | ~/.macify/System/Library/  | macOS frameworks         |
| /dev/               | /dev/ (pass-through)       | Real device files        |
| /proc/              | /proc/ (pass-through)      | Linux procfs             |
| /sys/               | /sys/ (pass-through)       | Linux sysfs              |
| /tmp/               | /tmp/ (pass-through)       | Shared temp directory    |
| ~/Library/          | ~/.macify/Library/         | macOS-style user Library |

Translation happens in `src/prefix.c` (`macify_translate_path`).

## 9. $INODE64 Symbol Aliases

macOS provides `stat$INODE64`, `lstat$INODE64`, `fstat$INODE64`,
`opendir$INODE64`, `readdir$INODE64` as aliases for the 64-bit
inode variants. Many macOS binaries import these names directly.

The shim exports these symbols and translates the struct layouts.
Critically, these wrappers do their own path translation directly
(not delegating to `macify_stat` etc.) because the caller check
would fail (return address is in the shim, not macOS text).

## 10. $DARWIN_EXTSN Symbol Aliases

macOS provides `fopen$DARWIN_EXTSN`, `fdopen$DARWIN_EXTSN`, etc.
as macOS-specific extensions. The loader strips the `$` suffix
during symbol resolution to find the base function.

## 11. Termcap Functions

macOS ncurses exports `tgetent`, `tgoto`, `tputs`, `tgetstr`,
`tgetflag`, `tgetnum` and the global variables `BC`, `PC`, `UP`.

Linux's ncurses does NOT export `BC`/`PC`/`UP`, and on some
distros (Artix, Arch) doesn't even export the termcap functions.

The shim exports `BC`/`PC`/`UP` as globals and provides
`tgetent`/`tgoto`/`tputs`/etc. wrappers that delegate to the
real implementations from libtinfo/libncursesw if available,
falling back to xterm-compatible capability strings.

## 12. environ

macOS binaries access `environ` via GOT, which resolves to glibc's
`__environ`. But macify's `environ` (updated by `setenv`) is a
different variable. The loader overwrites the environ GOT entry
with `&environ` (macify's environ) so the macOS binary sees the
correct environment including `PATH`, `MACIFY_BINARY`, etc.
