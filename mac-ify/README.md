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

# Run a macOS binary
LD_LIBRARY_PATH=build ./build/macify tests/real/jq_darwin --version

# Quiet mode (suppress loader diagnostics)
LD_LIBRARY_PATH=build ./build/macify -q tests/real/jq_darwin --version

# Run the unit test suite
make test
```

## Debugging

```bash
# Verbose loader output (default — shows segment mapping, fixups, bindings)
LD_LIBRARY_PATH=build ./build/macify tests/real/jq_darwin --version

# Disable fast-path patching (force SIGILL slow path for all syscalls)
LD_LIBRARY_PATH=build ./build/macify --no-fast-path tests/binaries/bench.bin

# Trace file I/O operations
MACIFY_TRACE_OPEN=1 LD_LIBRARY_PATH=build ./build/macify tests/real/sd_macos 'old' 'new' file.txt

# Trace network operations
MACIFY_TRACE_NET=1 LD_LIBRARY_PATH=build ./build/macify tests/real/curl_macos http://localhost:8080

# Trace ioctl calls (terminal)
MACIFY_TRACE_IOCTL=1 LD_LIBRARY_PATH=build ./build/macify tests/real/htop_macos
```

The crash handler prints registers, stack dump, and instruction bytes on SIGSEGV/SIGBUS/SIGFPE.

## Documentation

- `ARCHITECTURE.md` — design rationale, component walkthrough
- `ROADMAP.md` — phased plan

## Legal

Mac-ify ships only its own code. It does not bundle, link, or distribute Apple's binaries, frameworks, or private headers. The Mach-O format is publicly documented in `<mach-o/loader.h>`.

## License

TBD.
