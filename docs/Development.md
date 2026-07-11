# Development Guide

## Building

```
make            # Build everything (shim + loader + test binaries)
make clean      # Remove all build artifacts
make test       # Run unit tests
make shell      # Run interactive macOS bash
make install    # Install to /usr/local (or PREFIX=...)
make uninstall  # Remove installed files
```

## Testing macOS Binaries

### Non-interactive

```
macify-shell 'echo hello | sort | wc -l'
```

### Interactive

```
macify-shell
```

### Debug Mode

```
macify-debug ~/.macify/usr/bin/awk 'BEGIN {print "test"}' 2>report.txt
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
| MACIFY_SHIM_DEBUG     | Shim base address                       |
| MACIFY_VERIFY_HANDLER | Signal handler installation verification|

## Workarounds

| Variable       | Purpose                                    |
|----------------|--------------------------------------------|
| MACIFY_NO_FORK | Disable fork() (sort hangs in child process)|
| MACIFY_PREFIX  | Custom prefix directory (default ~/.macify) |
| MACIFY_BINARY  | Path to macify loader (set by wrapper)      |

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
  macify          Wrapper script
  macify-shell    Interactive shell launcher
  macify-debug    Diagnostic tool
  macify-init     Prefix initializer
  macify-setup-rootfs    Install macOS binaries into prefix
  macify-setup-homebrew  Download Homebrew bottles
  fetch_binaries.sh      Download macOS test binaries

tests/            Test suite
  run_tests.py    Unit test runner
  binaries/       Generated Mach-O test binaries
  real/           Downloaded macOS binaries for integration tests
```

## Adding a New Translation

1. Identify the macOS function that needs translation
2. Add a shim function in the appropriate file under `shim/`
3. Export it with `__asm__("function_name")`
4. If the struct layout differs, define `struct macos_*` and translate
5. Test with a macOS binary that uses the function
6. Add the translation to `docs/Translation.md`

## Prefix Setup

First-time setup is automatic when running `macify-shell`. It:
1. Creates `~/.macify/` directory structure
2. Downloads macOS bash from Homebrew
3. Downloads dylib dependencies (readline, ncurses, gettext)
4. Copies macOS coreutils from `tests/real/` into the prefix
5. Creates config files (/etc/shells, etc.)

To manually set up: `bash scripts/macify-setup-rootfs`
To fetch test binaries: `bash scripts/fetch_binaries.sh`
