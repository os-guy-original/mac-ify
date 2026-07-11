# Architecture

Macify is a macOS binary translator for Linux. It loads and runs
Mach-O x86_64 binaries on Linux by translating syscalls, data
structures, and filesystem paths at runtime.

## Components

### Loader (`src/`)

Parses Mach-O headers, maps segments into memory, processes
chained fixups and bind opcodes, resolves symbols, patches syscall
instructions, and jumps to the binary's entry point.

Key files:
- `main.c` — Entry point, load command processing, GOT resolution
- `segments.c` — Segment mapping, symbol resolution (`resolve_symbol`)
- `fixups.c` — LC_DYLD_INFO / chained fixups interpreter
- `macho_dylib.c` — Mach-O dylib loader (for readline, ncurses, etc.)
- `runtime.c` — Stack setup, signal handler installation, main() call
- `prefix.c` — Path translation (`macify_translate_path`)
- `syscall/` — BSD to Linux syscall number and argument translation

### Shim (`shim/`)

A shared library loaded via `LD_LIBRARY_PATH` that intercepts all
libc calls. macOS binaries call into the shim instead of glibc
directly. The shim translates arguments and delegates to glibc.

Key files:
- `shim_core.c` — Globals (environ, BC/PC/UP, errno), termcap wrappers
- `shim_spawn.c` — execve/posix_spawn path translation
- `io/flags.c` — open/openat flag translation (O_CREAT, O_NONBLOCK, etc.)
- `io/file.c` — stat/lstat/fstat struct translation, termios, $INODE64 shims
- `io/process.c` — fork/wait/pipe, FILE* management (fread/fgetc/fgets)
- `io/dirent.c` — opendir/readdir struct translation
- `io/glob.c` — glob_t struct translation
- `io/libintl.c` — gettext function shims (libintl_dcgettext, etc.)
- `signal/` — sigaction/sigprocmask signal number translation
- `sys/stubs.c` — macOS-specific stubs (getattrlist, mach_*, etc.)

### Shim Library (`build/libmacify_shim.so`)

Loaded as the first dylib (ordinal 0) before any LC_LOAD_DYLIB
processing. This ensures all symbols (BC, PC, UP, tgetent, etc.)
are available when dylib GOTs are resolved.

### Prefix (`~/.macify/`)

Virtual macOS filesystem. macOS binaries see `/` as the prefix root.
See [Translation.md](Translation.md) for path translation rules.

## Data Flow

1. User runs `macify <binary>` or `macify-shell '<command>'`
2. Loader reads Mach-O headers, maps segments with PIE slide
3. Shim is preloaded (dlopen) as g_dylibs[0]
4. LC_LOAD_DYLIB entries processed: Mach-O dylibs loaded, system
   libraries mapped to shim + libc
5. Chained fixups / bind opcodes resolved via resolve_symbol()
6. Syscall instructions patched (0x0F 0x05) with Linux syscall numbers
7. Stack set up with macOS-style layout (argc, argv, envp, apple)
8. Signal handlers installed (SIGSEGV, SIGABRT, SIGBUS, SIGFPE)
9. Control jumps to binary's entry point (LC_MAIN or LC_UNIXTHREAD)
10. Binary runs; all libc calls go through shim for translation
