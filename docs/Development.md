# Development Guide

## Building

```
make            # Build everything (shim + loader + test binaries)
make clean      # Remove all build artifacts
make test       # Run unit tests
make test-real  # Regression harness over fetched real macOS binaries
make test-smoke # Real-binary --version smoke tests
make shell      # Interactive macOS bash (same as: macify shell)
make install    # Install to /usr/local (or PREFIX=...)
make uninstall  # Remove installed files
```

Object files compile into `build/obj/{src,shim}` rather than the source
trees. Strict and sanitizer builds compose via two knobs:

```
make WERROR=-Werror                                       # warnings are errors
make SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
make asan       # full clean rebuild with both of the above
```

## The macify CLI

`scripts/macify` is the single front door; it works from the source
tree and from an installed prefix:

```
macify <binary> [args...]    run a macOS binary
macify shell [command]       interactive macOS bash inside the prefix
macify init                  initialize/repair the prefix
macify doctor                environment & prefix health check
macify debug <binary> [...]  verbose diagnostics for issue reports
```

Global options: `--prefix <dir>`, `-v/--verbose`. `LD_LIBRARY_PATH` is
intentionally not set anywhere — the loader locates the shim next to
itself via `/proc/self/exe`; exporting it has caused futex deadlocks on
some systems.

## Testing macOS Binaries

### Non-interactive

```
macify shell 'echo hello | sort | wc -l'
```

(`scripts/macify-shell '...'` still works as a compatibility wrapper.)

### Interactive

```
macify shell
```

Line editing is disabled by default (`--noediting`) for stability;
opt in with `MACIFY_USE_READLINE=1`.

### Health check

```
macify doctor
```

Verifies shim presence, prefix state, macOS bash, and runs a live
functional probe through prefix bash.

### Debug Mode

```
macify debug ~/.macify/usr/bin/awk 'BEGIN {print "test"}' 2>report.txt
```

This collects all diagnostic output (verbose loader, trace flags,
crash reports, GOT resolution) into a single report.

## Trace Flags

Set these environment variables to enable tracing:

| Variable              | What it traces                          |
|-----------------------|-----------------------------------------|
| MACIFY_TRACE_OPEN     | open, stat, opendir, isatty calls       |
| MACIFY_TRACE_READ     | fread, fgetc, fgets calls               |
| MACIFY_TRACE_FORK     | fork, vfork, waitpid, wait4 calls       |
| MACIFY_TRACE_SPAWN    | posix_spawn, execve, execvp calls       |
| MACIFY_TRACE_SIGNAL   | sigaction, sigprocmask calls            |
| MACIFY_TRACE_EXIT     | exit, _exit calls                       |
| MACIFY_TRACE_RECOVERY | Crash handler recovery decisions        |
| MACIFY_TRACE_LOCALE   | setlocale, locale calls                 |
| MACIFY_TRACE_SIGILL   | Slow-path syscall faults                |
| MACIFY_TRACE_FIXUPS   | Chained fixup / bind processing         |
| MACIFY_TRACE_PTHREAD  | pthread_create calls through the shim   |
| MACIFY_TRACE_MUTEX    | Interposed mutex lock/unlock            |
| MACIFY_SHIM_DEBUG     | Shim base address                       |
| MACIFY_VERIFY_HANDLER | Signal handler installation verification|

## Workarounds

| Variable       | Purpose                                    |
|----------------|--------------------------------------------|
| MACIFY_NO_FORK | Disable fork() (sort hangs in child process)|
| MACIFY_PREFIX  | Custom prefix directory (default ~/.macify) |
| MACIFY_BINARY  | Path to macify loader (set by wrapper)      |
| MACIFY_USE_READLINE=1 | Enable readline in interactive shell (libedit crashes mid-session otherwise) |
| MACIFY_LENIENT_SYSCALLS=1 | Return ENOSYS on unimplemented syscalls instead of exiting |

## Code Layout

```
src/              Loader (ELF binary)
  main.c          Entry point, load commands, GOT
  segments.c      Segment mapping, resolve_symbol()
  fixups.c        Bind/rebase opcode interpreter
  macho_dylib.c   Mach-O dylib loader
  runtime.c       Stack setup, signal handlers, main() call
  prefix.c        Path translation
  syscall/        Syscall number/argument translation

shim/             Shim (shared library)
  shim_core.c     Globals, termcap wrappers
  shim_spawn.c    exec/posix_spawn translation
  io/             I/O function overrides
    flags.c       open flags, mmap flags
    file.c        stat, termios, $INODE64
    process.c     fork, FILE* management, fread/fgetc
    dirent.c      opendir/readdir
    glob.c        glob_t translation
    libintl.c     gettext shims
  signal/         Signal translation
  sys/            macOS-specific stubs
  pthread/        pthread overrides

scripts/          User-facing scripts
  macify          Front-door dispatcher (run/shell/init/doctor/debug)
  macify-shell    Compatibility wrapper (forwards to: macify shell)
  macify-debug    Diagnostic tool
  macify-init     Prefix initializer
  macify-setup-rootfs    Install macOS binaries into prefix
  macify-setup-homebrew  Download Homebrew bottles
  fetch_binaries.sh      Download macOS test binaries
  gen_macho.py           Generate synthesized Mach-O test binaries

tests/            Test suite
  run_tests.py    Synthesized Mach-O unit tests (runner)
  real_regression.py  Real-binary regression harness with output assertions
  real_smoke.sh  Real-binary --version smoke tests
  real_functional.sh  Real-binary comprehensive functional tests
  binaries/       Generated Mach-O test binaries (built by gen_macho.py)
  real/           Downloaded macOS binaries for integration tests (fetched on demand)
```

Build objects live under `build/obj/{src,shim}`; final artifacts are
`build/macify` and `build/libmacify_shim.so`.

## Adding a New Translation

1. Identify the macOS function that needs translation
2. Add a shim function in the appropriate file under `shim/`
3. Export it with `__asm__("function_name")`
4. If the struct layout differs, define `struct macos_*` and translate
5. Test with a macOS binary that uses the function
6. Add the translation to `docs/Translation.md`

## Prefix Setup

First-time setup is automatic when starting a shell. It:
1. Creates `~/.macify/` directory structure
2. Downloads macOS bash from Homebrew
3. Downloads dylib dependencies (readline, ncurses, gettext)
4. Copies macOS coreutils from `tests/real/` into the prefix
5. Creates config files (/etc/shells, etc.)

To initialize manually: `macify init` (or `bash scripts/macify-setup-rootfs`)
To fetch test binaries: `bash scripts/fetch_binaries.sh`
To verify everything:  `macify doctor`
