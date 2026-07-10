# Mac-ify Roadmap

## Goal

Run real macOS x86_64 binaries on Linux. No emulation, no framework translation — just syscall ABI translation and symbol resolution.

## Done

- Mach-O loader (segments, sections, PIE/ASLR, chained fixups, legacy binds)
- Syscall translation (dual-path: fast immediate patching + SIGILL slow path)
- Symbol resolution (shim → libc → libm → extra libraries → $-suffix strip)
- Extra library loading (libncurses, libz, libedit, libssl, libcrypto, etc.)
- File I/O struct translation (stat, fcntl/flock, dirent)
- Network sockaddr translation (IPv4 + IPv6, getaddrinfo layout)
- Mach kernel API stubs (host_statistics, proc_pidinfo, task_info, etc.)
- Mach semaphore implementation (semaphore_create/destroy/signal/wait/timedwait)
- CoreFoundation / IOKit / ObjC runtime stubs
- Terminal ioctl translation (termios, TIOCGWINSZ)
- posix_spawn struct translation (macOS → Linux)
- _DefaultRuneLocale with correct macOS _CTYPE flag values
- pthread_atfork dlvsym fix for glibc 2.34+
- pthread_setname_np ABI translation (macOS 1-arg → Linux 2-arg)
- LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB / LC_LAZY_LOAD_DYLIB support
- Go binary support: GS base setup, sigaction translation, SA_ONSTACK
- Signal stack allocation (sigaltstack) for SA_ONSTACK handlers
- SIGILL/SIGSEGV/SIGBUS handler protection
- sysconf parameter translation (macOS _SC_* → Linux _SC_*)
- OpenSSL delegation to real libssl.so.3 / libcrypto.so.3
- Binary patching: getc macro + __SEOF/__SERR check patching
- Full FS path translation (fopen, mkdir, unlink, rename, *at functions)
- Wine-like prefix (~/.macify/) with macOS filesystem structure
- macify-shell (like `wine cmd`) — interactive shell with auto Mach-O detection

### Working binaries (150+ tested, all pass)

jq, ripgrep, fd, bat, xsv, sd, hyperfine, tree, curl (HTTP + HTTPS + TLS 1.2/1.3),
wget, htop, procs, sqlite3 (SQL execution), dust, starship, zoxide, rclone,
neovim (--version), comm, nl, cut, sed, strings, sort, uniq, cat, ls, and 120+ more

## Next

- Improve interactive neovim (needs more CoreServices stubs)
- Improve Go binary stability (rclone interactive mode)
- Add more macOS framework stubs (Security, Kerberos)
- Test more complex pipelines and real-world usage patterns
- Consider macOS ARM64 support (future)
