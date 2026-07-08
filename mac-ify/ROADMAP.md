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
- CoreFoundation / IOKit / ObjC runtime stubs
- Terminal ioctl translation (termios, TIOCGWINSZ)
- posix_spawn struct translation (macOS → Linux)
- _DefaultRuneLocale with correct macOS _CTYPE flag values
- stdio buffer flush before exit
- pthread_atfork dlvsym fix for glibc 2.34+
- pthread_setname_np ABI translation (macOS 1-arg → Linux 2-arg)
- LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB / LC_LAZY_LOAD_DYLIB support
- Go binary support: GS base setup (wrgsbase), sigaction syscall translation,
  SA_ONSTACK enforcement for Go signal handler compatibility
- Signal stack allocation (sigaltstack) for SA_ONSTACK handlers
- SIGILL/SIGSEGV/SIGBUS handler protection (prevents macOS binary from
  replacing macify's critical signal handlers)

### Working binaries (26/28 tests pass)

jq, ripgrep, fd, bat, xsv, sd, hyperfine, tree, curl (--version + HTTP + HTTPS),
wget, htop (--version), procs, sqlite3 (--version AND full SQL execution),
dust (disk usage scanning), starship (--version + session + preset),
zoxide (--version)

## In progress

- **rclone (Go binary)**: Go runtime initializes, creates goroutines, starts GC,
  but crashes with `runtime·unlock: lock count` — a deep Go runtime locking issue.
  Root cause likely: signal delivery during locked sections corrupts lock state.
  Progress: Go's rt0_go entry, schedinit, osinit, goroutine creation, and GC
  init all work. The crash occurs during GC scavenge goroutine execution.
- **htop interactive**: ncurses initializes, anti-hooking check causes early exit
- **neovim**: needs more CoreServices stubs

## Next

- Investigate Go runtime lock count issue (signal interference with locks?)
- Bypass or satisfy htop's anti-hooking check
- Add more CoreServices stubs for neovim
- Test more real-world usage patterns (pipelines, file I/O, network)
