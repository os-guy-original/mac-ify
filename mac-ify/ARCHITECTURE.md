# Mac-ify Architecture

> How Mac-ify runs macOS applications on Linux **without** framework-level translation.

## 1. Design Principle

Darling, the existing macOS-on-Linux project, fails because it tries to translate the *entire* Apple framework stack (Cocoa, AppKit, Foundation, CoreGraphics, Metal, ...) onto Linux primitives. The translation surface is enormous, every private framework call is a potential landmine, and the result is "kind of works for some apps" forever.

**Mac-ify takes a different position:**

1. The app's own machine code runs **natively** on the CPU. No JIT, no emulation, no IR lifting in the hot path.
2. Apple's framework binaries are **never bundled**. We do not ship Apple's `.dylib` / `.framework` files. We provide our own Linux-native re-implementations of those frameworks, one at a time, as needed.
3. The only "translation" we permit is at the **syscall ABI boundary** — macOS x86_64 uses BSD-class syscall numbers (`0x2000000` prefix), Linux uses different numbers. We patch this at load time. This is one layer of indirection, not a tower of them.

This document describes how each piece works.

## 2. High-Level Architecture

```
                ┌─────────────────────────────────────┐
                │           User invokes              │
                │       macify run Foo.app            │
                └──────────────┬──────────────────────┘
                               │
                               ▼
                ┌─────────────────────────────────────┐
                │         macify-run (ELF)            │
                │  ┌───────────────────────────────┐  │
                │  │ 1. Mach-O Parser              │  │
                │  │    - header, segments,        │  │
                │  │      symtab, dyld_info        │  │
                │  └───────────────┬───────────────┘  │
                │                  ▼                  │
                │  ┌───────────────────────────────┐  │
                │  │ 2. Segment Mapper             │  │
                │  │    mmap each LC_SEGMENT_64    │  │
                │  │    with correct prot          │  │
                │  └───────────────┬───────────────┘  │
                │                  ▼                  │
                │  ┌───────────────────────────────┐  │
                │  │ 3. Symbol Binder              │  │
                │  │    resolve @rpath / dyld      │  │
                │  │    rewrites → our shims       │  │
                │  └───────────────┬───────────────┘  │
                │                  ▼                  │
                │  ┌───────────────────────────────┐  │
                │  │ 4. Syscall Patcher            │  │
                │  │    scan .text for 0F 05       │  │
                │  │    rewrite → UD2              │  │
                │  └───────────────┬───────────────┘  │
                │                  ▼                  │
                │  ┌───────────────────────────────┐  │
                │  │ 5. SIGILL Handler             │  │
                │  │    macOS syscall # → Linux    │  │
                │  │    execute, fixup rax/rip     │  │
                │  └───────────────┬───────────────┘  │
                │                  ▼                  │
                │  ┌───────────────────────────────┐  │
                │  │ 6. Entry Jumper               │  │
                │  │    set rip from LC_UNIXTHREAD │  │
                │  │    or LC_MAIN                 │  │
                │  └───────────────┬───────────────┘  │
                └──────────────────┼──────────────────┘
                                   │
                                   ▼
                ┌─────────────────────────────────────┐
                │       App's native code runs        │
                │     (untouched, full CPU speed)     │
                └─────────────────────────────────────┘
```

## 3. Components in Detail

### 3.1 Mach-O Parser (`macho.c`)

Parses the Mach-O header and walks all load commands. Currently supports:

- `MH_MAGIC_64` (0xFEEDFACF) — 64-bit Mach-O
- `CPU_TYPE_X86_64` (0x01000007) — only x86_64 for now (ARM64 in Phase 5)
- `MH_EXECUTE` filetype (we don't load dylibs or bundles yet)
- `LC_SEGMENT_64` (0x19) — segment definitions
- `LC_UNIXTHREAD` (0x05) — entry point via thread state (classic)
- `LC_MAIN` (0x80000028) — entry point via main() (modern, requires dyld)
- `LC_SYMTAB` (0x02) — symbol table (parsed, not yet used)
- `LC_DYSYMTAB` (0x0B) — dynamic symbol info (parsed, not yet used)

Future phases will add `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_DYLD_INFO`, `LC_CODE_SIGNATURE`.

### 3.2 Segment Mapper (`loader.c`)

For each `LC_SEGMENT_64`:

1. Compute the page-aligned address range `[vmaddr, vmaddr + vmsize)`
2. `mmap()` an anonymous region with `PROT_NONE` to reserve the address range
3. For each page that has file content, `mmap()` the file with `MAP_FIXED` and the correct protection
4. For zero-fill pages (BSS, `__PAGEZERO`), keep them as anonymous zero pages
5. Apply protection bits from `initprot`:
   - `r` → `PROT_READ`
   - `w` → `PROT_WRITE`
   - `x` → `PROT_EXEC`

`__PAGEZERO` (the catch-all NULL-page guard at vmaddr 0) is mapped as `PROT_NONE` to catch null derefs the same way macOS does.

### 3.3 Syscall Trampoline — Dual-Path Design

**The problem:** macOS x86_64 syscall numbers live in the `0x2000000` range. The `syscall` instruction (`0F 05`) on Linux looks at `rax` and dispatches to the *Linux* syscall table. So a macOS binary doing `write(1, buf, n)` issues `rax=0x2000004`, but on Linux that's an out-of-range number and returns `ENOSYS`.

Two paths, picked at load time.

#### Fast Path — Immediate Patching (most syscalls)

The canonical macOS syscall setup is:

```asm
mov eax, 0x2000004      ; B8 04 00 00 20   (load BSD syscall # as imm32)
mov edi, 1              ; setup arg 1
lea rsi, [rip + msg]    ; setup arg 2
mov edx, 16             ; setup arg 3
syscall                 ; 0F 05
```

The `mov eax, 0x2000XXXX` loads a **compile-time constant**. At load time, we:

1. Scan executable segments for `0F 05` (syscall).
2. For each, look backward up to 32 bytes for the pattern `B8 XX XX 00 20` (mov eax, 0x2000XXXX). Skip if preceded by `0x48` (REX.W → mov rax, imm64).
3. Extract the BSD syscall number from the immediate.
4. If the BSD syscall has a Linux equivalent **and** needs no argument translation **and** is not `exit`:
   - **Rewrite the immediate** in-place: `B8 XX XX 00 20` → `B8 YY YY 00 00` (Linux syscall #).
   - **Leave the `syscall` instruction alone** — it executes natively!

The app's code now issues the Linux syscall directly. **Zero signal-handler overhead.** The syscall runs at full native speed — indistinguishable from a binary compiled for Linux.

#### Slow Path — SIGILL Handler (translation needed)

For syscalls that need argument translation (e.g., `open()` has different flag values on macOS vs Linux), or for `exit` (where we want to print stats before terminating):

1. Patch `0F 05` → `0F 0B` (`UD2`, raises `SIGILL`).
2. Install a `SIGILL` handler.
3. When `SIGILL` fires:
   - Extract saved register state from `ucontext_t`.
   - `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` = the syscall args (same on both ABIs).
   - `rax` = macOS syscall number.
   - **O(1) flat-array lookup**: `linux_nr = bsd_to_linux[rax & 0xFFFFFF]` (no switch statement).
   - Translate per-syscall arguments if needed (e.g., `open()` flags).
   - Execute the Linux syscall via inline `syscall` instruction.
   - Store result in `rax` in the `ucontext_t`, advance `rip` past the 2-byte `UD2`, return.
4. For `exit` (BSD 1): print stats, then call `exit_group`.

#### Why this is not "translation" in the Darling sense

- Darling translates at the framework level (Cocoa → GTK, Foundation → custom). Every ObjC message send, every framework call goes through translation.
- Mac-ify only touches the syscall instruction itself. App code runs natively. Framework code (when we have it) will run natively. Only the ~350 syscall numbers get remapped.
- With the fast path, **most syscalls run at full native speed with zero overhead**. Only syscalls with argument-translation needs (open, mmap, fcntl, ioctl, etc.) go through the SIGILL handler.

#### Performance: measured 22-25x speedup

Benchmark: 100,000 `write()` syscalls to `/dev/null`:

| Path | Time | Per-syscall overhead |
|------|------|---------------------|
| Fast path (immediate patching) | ~31 ms | ~0 ns (native) |
| Slow path (SIGILL handler) | ~730 ms | ~7 µs (signal delivery) |
| **Speedup** | **~23x** | |

The slow path's ~7 µs per syscall is dominated by Linux signal delivery overhead (kernel saves full register state, delivers signal, restores). The fast path has zero overhead — the rewritten `mov eax` + native `syscall` is exactly what a Linux binary would do.

#### The 32-byte backward scan

The patcher looks backward up to 32 bytes from each `syscall` for the `mov eax, 0x2000XXXX` pattern. This window covers syscall setups with up to 4 arguments:

```
mov eax, ...     (5 bytes)   ; syscall #
mov edi, ...     (5 bytes)   ; arg 1
lea rsi, ...     (7 bytes)   ; arg 2
mov edx, ...     (5 bytes)   ; arg 3
mov r10, ...     (5-7 bytes) ; arg 4 (if present)
syscall          (2 bytes)
```

Total: 24-29 bytes. The 32-byte window covers this. 5-arg and 6-arg syscalls (rare: `select`, `mmap`, `pselect6`) fall through to the slow path, which is fine.

#### Safety: the REX prefix check

The byte before `B8` is checked for any REX prefix (`0x40`-`0x4F`). If present, this is not `mov eax, imm32` — it's `mov rax, imm64` (REX.W, 0x48), `mov r8d, imm32` (REX.B, 0x41), or another REX-prefixed form. We skip these to avoid misidentifying the instruction and corrupting a 64-bit immediate or rewriting the wrong register's load.

#### Known limitation: rcx/r11 preservation

The x86_64 `syscall` instruction architecturally clobbers `rcx` (saves return rip) and `r11` (saves rflags). Real macOS apps never use rcx/r11 across a syscall.

- **Fast path**: matches real hardware — rcx/r11 are clobbered.
- **Slow path**: the SIGILL handler accidentally preserves rcx/r11 (it doesn't write them back to the ucontext). This is MORE forgiving than real macOS.

Apps that correctly avoid rcx/r11 across syscalls work identically in both paths. Apps that incorrectly use rcx/r11 across syscalls would work in the slow path but fail in the fast path — and would also fail on real macOS. The fast path is the "more correct" behavior.

#### Return value convention

Linux raw syscalls return `-errno` on failure (e.g., `-9` for EBADF). macOS raw syscalls return `-1` on failure and set errno via the thread-local `__errno()` pointer. Real macOS apps check for `-1`, not `-errno`.

The SIGILL handler converts Linux's `-errno` returns to macOS's `-1` convention. If `result < 0 && result > -4096` (the errno range), we replace it with `-1`. Setting `errno` properly via macOS's `__errno()` requires a libSystem shim — deferred to Phase 2.

#### Argument translation

Most syscalls take the same arguments on macOS and Linux (file descriptors, pointers, sizes). A few take flag bitmasks or enumerated values whose numeric values differ between the two systems. Each is handled by a dedicated translator:

| Syscall | What differs | Translator |
|---------|--------------|------------|
| `open` (5) | flag bits (O_CREAT, O_TRUNC, etc.) | `translate_open_flags` |
| `mmap` (197) | flag bits (MAP_ANON vs MAP_ANONYMOUS) | `translate_mmap_flags` |
| `kill` (37) | signal numbers (SIGURG, SIGUSR1, etc.) | `translate_kill_signal` |
| `fcntl` (92) | cmd values (F_GETLK, F_DUPFD_CLOEXEC, etc.) | `translate_fcntl_cmd` |
| `madvise` (75) | advice values (MADV_FREE) | `translate_madvise` |

An audit confirmed that several syscalls I initially flagged as "needing translation" actually have identical constants on both systems: `mprotect` (prot bits), `msync` (flags), `flock` (op), `shutdown` (how), `socket` (type), `getrusage` (who + struct layout). These were un-flagged.

Two syscalls have deep structural differences that can't be fixed by translating a single argument — deferred to Phase 2:
- `sigprocmask` — `sigset_t` layout differs (128 bytes on macOS, 8 bytes on Linux)
- `fcntl` with `F_GETLK`/`F_SETLK` — `struct flock` layout differs (24 bytes macOS, 32 bytes Linux)

### 3.4 Entry Jumper (`entry.c`)

After everything is set up, we need to jump to the app's entry point. We:

1. Read the entry RIP from `LC_UNIXTHREAD` (or `LC_MAIN`).
2. Set up a stack: `argc`, `argv[]`, NULL, `envp[]`, NULL, `apple[]` (macOS passes the executable path here).
3. Jump to the entry point via inline assembly.

We **do not** call dyld. The app's entry point is its true `main()` (or `_main` in Mach-O symbol terms) — for hand-crafted binaries this is the actual start. For real macOS apps, we'll need to load and run `dyld` itself, which is a much bigger task (Phase 4).

## 4. Test Binary Format

We can't compile Mach-O binaries on Linux without a cross-toolchain. Instead, we **hand-craft** minimal Mach-O x86_64 binaries in Python. Each test binary is:

- A valid Mach-O 64-bit executable
- Self-contained (no dylib dependencies)
- Uses raw macOS syscalls (no libSystem)
- Small enough to audit by hand

The generator (`scripts/gen_macho.py`) builds:

| Binary | What it does | macOS syscalls used |
|--------|--------------|---------------------|
| `hello.bin` | writes `Hello, Mac-ify!\n` to stdout | `write(1, buf, 16)` |
| `exit42.bin` | exits with code 42 | `exit(42)` |
| `argv.bin` | writes `argv[0]` to stdout | `write(1, argv[0], len)` |
| `compute.bin` | computes `sum(1..100)` and writes the decimal | `write(1, buf, n)`, `exit(0)` |
| `writefile.bin` | creates `/tmp/macify-test.txt` and writes "ok" | `open`, `write`, `close` |

These are the apps that "don't rely on huge Apple stuff" — they use only the BSD syscall surface, which is tiny and well-documented.

## 5. What is Intentionally Missing

To keep the first implementation honest and reviewable:

- **No dyld support.** Real macOS apps link against `libSystem.B.dylib`, `Foundation.framework`, etc., and rely on `dyld` to bind them at launch. We can't load those apps yet.
- **No code signature verification.** We trust the binary.
- **No PIE / ASLR randomization.** We load at the Mach-O's static vmaddr.
- **No ObjC runtime.** Apps that use `objc_msgSend` won't work yet.
- **No GUI.** No AppKit, no CoreGraphics, no window server.
- **No real `dyld_stub_binder`.** Lazy symbol binding is not implemented.

Each of these is a future phase (see `ROADMAP.md`).

## 6. Security Posture

Loading and executing untrusted Mach-O binaries is inherently dangerous. Mac-ify's threat model:

- **Trust assumption:** The user explicitly invokes `macify run` on a binary they intend to run. We do not auto-execute anything.
- **Memory safety in the loader:** The loader itself is C code that parses attacker-influenced data. We use bounds-checked accessors everywhere and `mmap` with explicit permissions.
- **No elevation:** Mac-ify never calls `setuid`, `setgid`, or `capset`. The loaded binary runs with the user's own privileges.
- **Syscall filtering:** Long-term, we'll wrap the loaded binary in a seccomp filter that blocks dangerous Linux syscalls the macOS app shouldn't be issuing (e.g. `bpf`, `kexec_load`). For now, all syscalls pass through.

## 7. License & Legal

Mac-ify ships only its own code. It does not bundle, link, or distribute Apple's binaries, frameworks, or private headers. Framework re-implementations are clean-room, written from public documentation and observed behavior, not from Apple's source.

The Mach-O file format is publicly documented in `<mach-o/loader.h>` and Apple's published OS X ABI references.
