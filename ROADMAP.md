# Mac-ify Roadmap

## Goal

Run real macOS x86_64 binaries on Linux. No emulation, no framework translation — just syscall ABI translation and symbol resolution.

## Done

- Mach-O loader (segments, sections, PIE/ASLR, chained fixups, legacy binds)
- Syscall translation (dual-path: fast immediate patching + SIGILL slow path)
- Symbol resolution (shim → libc → libm → extra libraries → $-suffix strip)
- Extra library loading (libncurses, libz, libedit, libssl, etc.)
- File I/O struct translation (stat, fcntl/flock, dirent)
- Network sockaddr translation (IPv4 + IPv6, getaddrinfo layout)
- Mach kernel API stubs reading from /proc (host_statistics64, proc_pidinfo, etc.)
- CoreFoundation / IOKit stubs
- Terminal ioctl translation (termios, TIOCGWINSZ)
- posix_spawn struct translation (macOS → Linux)
- _DefaultRuneLocale with correct macOS _CTYPE flag values
- stdio buffer flush before exit
- pthread_atfork dlvsym fix for glibc 2.34+

### Working binaries

jq, ripgrep, fd, bat, xsv, sd, hyperfine, tree, curl, wget, htop (--version), procs, sqlite3 (--version)

## In progress

- **htop interactive**: ncurses initializes, anti-hooking check (strstr on CF function bytes) causes early exit
- **sqlite3 SQL execution**: --version works, SQL queries crash (segfault without signal handler firing)
- **curl HTTPS**: --version works, TLS handshake needs investigation (IPv6 sockaddr + OpenSSL init)

## Next

- Fix sqlite3 SQL execution crash
- Bypass or satisfy htop's anti-hooking check
- Test curl/wget HTTPS against a local TLS server
- Test more real-world usage patterns (pipelines, file I/O, network)
