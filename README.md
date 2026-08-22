# Mac-ify

> Run macOS x86_64 binaries on Linux without framework-level translation.

## Why

Darling tries to translate the entire Apple framework stack onto Linux. That surface is too big. Mac-ify runs the app's own machine code natively and only translates the syscall ABI boundary. One layer of indirection, not a tower of them.

## What this is

A Mach-O loader and syscall translator for x86_64. It loads macOS binaries, patches their `syscall` instructions, resolves symbols through a shim + glibc, and jumps to `main()`. No JIT, no emulation — the app's code runs on the real CPU.

## Running

```bash
# Build
make

# Fetch test binaries (real macOS x86_64 binaries)
./scripts/fetch_binaries.sh

# Initialize the prefix (~/.macify) — also happens on first shell use
./scripts/macify init

# Run a macOS binary
./scripts/macify tests/real/jq_darwin --version

# Interactive macOS bash inside the prefix
./scripts/macify shell

# Health check
./scripts/macify doctor

# Run the unit test suite
make test

# Run the real-binary regression harness (needs fetch_binaries.sh first)
make test-real

# Run real-binary smoke tests
make test-smoke

# Run real-binary functional tests (slow, comprehensive)
make test-functional
```

The dispatcher works from the source tree and after `make install`,
and never needs `LD_LIBRARY_PATH` — the loader locates the shim next
to itself via `/proc/self/exe`.

## Debugging

```bash
# Verbose loader output (shows segment mapping, fixups, bindings)
./scripts/macify -v tests/real/jq_darwin --version

# Disable fast-path patching (force SIGILL slow path for all syscalls)
LD_LIBRARY_PATH=build ./build/macify --no-fast-path tests/binaries/bench.bin

# Trace file I/O operations
MACIFY_TRACE_OPEN=1 ./scripts/macify tests/real/sd_macos 'old' 'new' file.txt

# Trace network operations
MACIFY_TRACE_NET=1 ./scripts/macify tests/real/curl_macos http://localhost:8080

# Trace ioctl calls (terminal)
MACIFY_TRACE_IOCTL=1 ./scripts/macify tests/real/htop_macos

# Return ENOSYS on unimplemented syscalls instead of exiting
MACIFY_LENIENT_SYSCALLS=1 ./scripts/macify tests/real/your_binary

# Full diagnostic report for issue filings
./scripts/macify debug tests/real/your_binary
```

The crash handler prints registers, stack dump, and instruction bytes on SIGSEGV/SIGBUS/SIGFPE.

## Documentation

- [`docs/Architecture.md`](docs/Architecture.md) — design rationale, component walkthrough
- [`docs/Development.md`](docs/Development.md) — build, test, and trace-flag guide
- [`docs/Translation.md`](docs/Translation.md) — syscall/flag/struct translation tables
- [`docs/xnu/`](docs/xnu/) — upstream Apple sources (xnu `syscalls.master`,
  `fcntl.h`) used as ground truth for the translation tables
- [`docs/macho/`](docs/macho/) — externally-fetched reference material on the Mach-O format
  (Wikipedia, Apple's "Overview of the Mach-O Executable Format", the OS X ABI
  Mach-O File Format Reference, the dyld repo README, and an in-depth
  walk-through of writing a Mach-O loader). Cited per-source.
- [`ROADMAP.md`](ROADMAP.md) — phased plan

## Legal

Mac-ify ships only its own code. It does not bundle, link, or distribute Apple's binaries, frameworks, or private headers. The Mach-O format is publicly documented in `<mach-o/loader.h>`.

## License

TBD.
