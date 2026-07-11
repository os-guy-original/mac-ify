# Architecture

Macify is a macOS binary translator for Linux — it loads and runs
Mach-O x86_64 binaries on Linux by translating syscalls, data
structures, and filesystem paths at runtime.

## Components

```
┌─────────────────────────────────────────────────────┐
│                    macify binary                     │
│  (src/) — Mach-O loader, segment mapper, fixup      │
│  interpreter, syscall patcher, prefix manager        │
├─────────────────────────────────────────────────────┤
│                 libmacify_shim.so                    │
│  (shim/) — Interposed C library that intercepts     │
│  all glibc calls and translates macOS → Linux        │
├─────────────────────────────────────────────────────┤
│                   ~/.macify/                         │
│  Prefix — Virtual macOS filesystem root             │
│  (like Wine's WINEPREFIX)                           │
└─────────────────────────────────────────────────────┘
```

### Loader (`src/`)

Parses Mach-O headers, maps segments into memory, processes
chained fixups / bind opcodes, resolves symbols, patches syscall
instructions, and jumps to the binary's entry point.

Key files:
- `main.c` — Entry point, load command processing, GOT resolution
- `segments.c` — Segment mapping, symbol resolution (`resolve_symbol`)
- `fixups.c` — LC_DYLD_INFO / chained fixups interpreter
- `macho_dylib.c` — Mach-O dylib loader (for readline, ncurses, etc.)
- `runtime.c` — Stack setup, signal handler installation, main() call
- `prefix.c` — Path translation (`macify_translate_path`)
- `syscall/` — BSD→Linux syscall number/argument translation

### Shim (`shim/`)

A shared library loaded via `LD_LIBRARY_PATH` that intercepts all
libc calls. macOS binaries call into the shim instead of glibc
directly. The shim translates arguments and delegates to glibc.

Key files:
- `shim_core.c` — Globals (environ, BC/PC/UP, errno), termcap wrappers
- `shim_spawn.c` — execve/posix_spawn path translation
- `io/flags.c` — open/openat flag translation (O_CREAT, O_NONBLOCK, etc.)
- `io/file.c` — stat/lstat/fstat struct translation, termios, $INODE64
- `io/process.c` — fork/wait/pipe, FILE* management (fread/fgetc/fgets)
- `io/dirent.c` — opendir/readdir struct translation
- `io/glob.c` — glob_t struct translation
- `io/libintl.c` — gettext function shims (libintl_dcgettext, etc.)
- `signal/` — sigaction/sigprocmask signal number translation
- `sys/stubs.c` — macOS-specific stubs (getattrlist, mach_*, etc.)

### Prefix (`~/.macify/`)

Virtual macOS filesystem. macOS binaries see `/` as the prefix root.
See [Translation.md](Translation.md) for path translation rules.
