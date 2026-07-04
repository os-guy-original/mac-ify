# Mac-ify Roadmap

A realistic, phased plan. Each phase produces something you can demo.

## Phase 0 — Recon & Setup ✅ 

- [x] Project structure, README, ARCHITECTURE.md
- [x] Decide language: C (loader) + Python (test binary generator)
- [x] Decide target: x86_64 macOS binaries on x86_64 Linux (host arch matches target arch)

## Phase 1 — Proof of Concept: Hand-Crafted Mach-O Hello World ✅

**Goal:** Run a hand-built Mach-O x86_64 binary on Linux and see correct output.

- [x] Mach-O parser (header, LC_SEGMENT_64, LC_UNIXTHREAD)
- [x] Segment mapper (mmap with proper prot, __PAGEZERO guard)
- [x] Syscall trampoline (UD2 patching + SIGILL handler + macOS→Linux number translation)
- [x] Entry jumper (stack setup + jump to entry)
- [x] Test binary generator (Python script that emits valid Mach-O)
- [x] 5 test binaries: hello, exit42, argv, compute, writefile
- [x] Test suite runner

**Success criteria:** `macify run tests/binaries/hello.bin` prints `Hello, Mac-ify!` and exits 0. ✅

## Phase 1.5 — Performance Optimization ✅

**Goal:** Make the syscall trampoline fast enough for real-world use.

- [x] Expand BSD syscall table from ~25 to ~80 entries (flat array, O(1) lookup)
- [x] Argument translation flags per-syscall (open flags done; mmap/fcntl/ioctl TODO)
- [x] **Immediate patching fast path** — for syscalls with constant number and no arg translation, rewrite `mov eax, 0x2000XXXX` → `mov eax, LINUX_XXX` at load time. The `syscall` instruction executes natively with zero signal-handler overhead.
- [x] Optimized SIGILL handler (flat array, `__builtin_expect`, no fprintf on hot path)
- [x] Stats counting (fast/slow site counts, slow-path invocation count)
- [x] `--no-fast-path` flag for benchmarking
- [x] Bench test binary (100,000 writes to /dev/null)

**Success criteria:** 22-25x speedup on 100,000-write benchmark (31ms fast path vs 730ms slow path). ✅

## Phase 1.6 — Argument Translation ✅

**Goal:** Complete argument translation for all syscalls where macOS and Linux disagree on argument values.

- [x] Audit which syscalls actually need translation (several were incorrectly flagged)
- [x] Un-flag syscalls with identical constants: mprotect, msync, flock, shutdown, socket, getrusage
- [x] `open()` flag translation (O_CREAT, O_TRUNC, etc.) — done
- [x] `mmap()` flag translation (MAP_ANON → MAP_ANONYMOUS) 
- [x] `kill()` signal number translation (SIGURG, SIGUSR1, SIGUSR2, etc.) 
- [x] `fcntl()` cmd translation (F_GETLK, F_SETLK, F_DUPFD_CLOEXEC, etc.) 
- [x] `madvise()` advice translation (MADV_FREE) 
- [x] Linux `-errno` → macOS `-1` return value convention 
- [x] Fix REX prefix check (0x40-0x4F, not just 0x48) — prevents misidentifying `mov r8d, imm32` as `mov eax, imm32`
- [x] Negative tests: verified each translator is actually necessary (disabling it causes the test to fail)

**Success criteria:** 9/9 tests pass, 22x speedup maintained, all translators verified via negative tests. ✅

**Deferred to Phase 2 (deep structural differences):**
- `sigprocmask` — sigset_t layout differs (128 bytes macOS vs 8 bytes Linux)
- `fcntl` with F_GETLK/F_SETLK — struct flock layout differs (24 bytes macOS vs 32 bytes Linux)
- `ioctl` cmd values — too complex, pass through (real apps may fail)
- `wait4` options — WCONTINUED bit differs (minor)
- Setting errno via macOS's `__errno()` pointer — needs libSystem shim

## Phase 2 — Dynamic Linking ✅

**Goal:** Load Mach-O binaries that use dynamic linking — LC_LOAD_DYLIB, LC_DYLD_INFO bind/rebase/lazy_bind opcodes, LC_MAIN entry, ASLR/PIE, named sections, __LINKEDIT segment, and a custom libSystem shim.

- [x] Parse `LC_LOAD_DYLIB` — record dylib name and ordinal
- [x] Parse `LC_DYLD_INFO_ONLY` — extract bind/rebase/lazy_bind bytecode offsets
- [x] Parse `LC_MAIN` — find entry point as offset from __TEXT
- [x] ULEB128 / SLEB128 readers (for bind/rebase bytecode)
- [x] **Rebase opcode interpreter** — adjusts internal pointers for load slide
- [x] **Bind opcode interpreter** — resolves external symbols, fills __got entries (non-lazy binds)
- [x] **Lazy bind opcode interpreter** — resolves lazy symbols eagerly at load time, fills __la_symbol_ptr entries
- [x] Multiple DONE-separated sequences in lazy bind bytecodes (one per lazy symbol)
- [x] Multiple dylibs (2 ordinals tested: libSystem.B.dylib + libobjc.A.dylib)
- [x] Stubs — code that jumps through __la_symbol_ptr to call lazy-bound functions
- [x] `call_main_and_exit()` — calls `main(argc, argv, envp, apple)` as a C function, exits with return value
- [x] **ASLR/PIE support** — detects `MH_PIE` flag, computes random slide via `mmap(NULL, ...)`, applies slide to all segment mappings, rebases, and entry points
- [x] **Section-level parsing** — parses `section_64` structs within segments; stores with slide applied to addr
- [x] **Section-aware syscall patching** — restricts patching to code sections, avoids false positives in data sections
- [x] **`__LINKEDIT` segment handling** — maps read-only; contains symbol table, string table, indirect symbol table, and bind/rebase bytecodes
- [x] **`LC_SYMTAB` + `LC_DYSYMTAB`** — parses symbol table (`nlist_64`), string table, indirect symbol table; `lookup_indirect_symbol()` ready for real dyld-style lazy binding
- [x] **Custom libSystem shim** (`libmacify_shim.so`) — provides macOS-specific functions glibc doesn't have:
  - `__errno()` — returns `int *` to thread-local errno (bridges to glibc's `__errno_location()`)
  - `_NSGetEnviron()` — returns `&environ`
  - `___progname` / `__progname` — program name globals
  - `__stack_chk_fail()` — stack canary handler
  - `_dyld_image_count()` / `_dyld_get_image_*()` — dynamic loader introspection
  - `mach_msg()`, `mach_task_self()`, `mach_thread_self()`, `mach_host_self()` — Mach trap stubs
  - `__memset_chk`, `__memcpy_chk`, `__memmove_chk`, `__strcpy_chk` — fortified memory functions
  - `objc_msgSend`, `objc_getClass`, `sel_registerName` — ObjC runtime stubs
  - `dispatch_async`, `dispatch_sync`, `dispatch_get_main_queue` — libdispatch stubs
  - `CFBundleGetMainBundle`, `CFRelease` — CoreFoundation stubs
  - `___assert_rtn` — macOS assertion function
  - `arc4random`, `arc4random_uniform`, `arc4random_buf` — random number functions
  - `NSLog`, `CFLog` — logging stubs
- [x] **Shim-first symbol resolution** — bind interpreter tries shim first, then libc.so.6 fallback
- [x] `hello_errno` test binary — calls `__errno()` from the shim (proves shim-first resolution works)
- [x] All 15 tests pass, 24x speedup maintained

**Key insight:** When a macOS binary calls a C library function (like `_write`), we bind it to glibc's equivalent. glibc's `write` issues a **native Linux syscall** — zero translation needed. For macOS-specific functions (like `__errno()`), the shim provides them directly.

**Shim-first resolution:** The loader dlopens `libmacify_shim.so` and `libc.so.6` for each `LC_LOAD_DYLIB`. When resolving a symbol, it tries the shim first (for macOS-specific functions), then falls back to libc (for standard C functions). This is transparent to the app — it just sees its symbols resolved.

**Success criteria:** `hello_errno.bin` calls `__errno()` — a function that exists in macOS libc but NOT in glibc (glibc has `__errno_location()` instead). The shim provides it, the bind resolves to the shim's address, and the binary successfully reads errno. ✅

**About real macOS binaries:** The loader has been tested with a **real macOS binary** — ripgrep 13.0.0 (x86_64, Rust, 4.5MB, PIE, 18 load commands, 5 segments, 3 dylibs, 123 lazy bind symbols). The loader successfully:
- Mapped all 5 segments (`__PAGEZERO`, `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`)
- Applied PIE slide (random load address)
- Parsed all 18 load commands including `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_BUILD_VERSION`
- Executed hundreds of rebases with the slide
- Resolved all 3 non-lazy binds (`___stack_chk_guard`, `__tlv_bootstrap` ×7 via `DO_BIND_ULEB_TIMES_SKIPPING_ULEB`, `dyld_stub_binder`)
- Resolved all 123 lazy binds (including `$NOCANCEL`, `$INODE64`, `$DARWIN_EXTSN` suffix stripping)
- Set up TLV (Thread-Local Variable) info: per-thread TLV blocks with `__thread_data`/`__thread_bss` initialization
- Set up argc/argv/executable path via `_NSGetArgc`/`_NSGetArgv`/`_NSGetExecutablePath`
- Ran module initializers (`__mod_init_func` section, if present)
- Forwarded `_Unwind_*` C++ exception functions to libgcc_s
- Called `main()` at the entry point

The binary crashes during Rust runtime initialization (inside main(), at TLV table iteration) because ripgrep's Rust runtime expects macOS-specific TLV initialization that our stubs don't fully replicate. The crash handler shows: `call [rdi]` (TLV thunk call) succeeds, but the subsequent `mov [rcx+rdx], rax` (storing the TLV result) hits unmapped memory because the Rust runtime's internal TLV table layout differs from what our shim provides.

**This is a runtime issue, not a loader issue.** The loader infrastructure — Mach-O parsing, segment mapping, PIE/ASLR, rebases, binds, lazy binds, section parsing, `__LINKEDIT` handling, symbol resolution, shim integration — all work correctly with a real macOS binary.

**Runtime support added:**
- **TLV (Thread-Local Variables)**: Full implementation — per-thread TLV blocks with `__thread_data` initialization and `__thread_bss` zeroing; `tlv_bootstrap` function in shim (with `_tlv_bootstrap` alias); loader registers TLV section info via `__macify_set_tlv_info()`; tested with `hello_tlv.bin`
- **C++ exception unwinding**: `_Unwind_*` functions forwarded to libgcc_s via dlopen/dlsym (13 functions)
- **Module initializers**: `__mod_init_func` section function pointers called before `main()`
- **Crash handler**: SIGSEGV/SIGBUS/SIGFPE handler prints register state and faulting address for debugging
- **argc/argv setup**: Loader calls `__macify_set_args()` to initialize `_NSGetArgc`/`_NSGetArgv`/`_NSGetExecutablePath`
- **`$`-suffix stripping**: In all bind opcodes including `DO_BIND_ULEB_TIMES_SKIPPING_ULEB`
- **Default bind type**: `BIND_TYPE_POINTER` (persists across DONE boundaries)

**About the ripgrep crash:** The loader successfully loads ripgrep, resolves all 126 symbols, sets up TLV, calls `main()`. The crash is at offset `0x3019ae` in `__TEXT` — inside Rust's `lang_start` runtime initialization. The crash handler shows: `call [rdi]` (TLV thunk call) succeeds, but `mov [rcx+rdx], rax` (storing the TLV result) hits unmapped memory. The Rust runtime's internal TLV table layout expects macOS-specific dyld behavior that requires deeper compatibility. This is a runtime issue, not a loader issue — the TLV mechanism itself works correctly (proven by `hello_tlv.bin`).

**Still TODO:**
- [ ] Get ripgrep to run past Rust runtime init (TLV table layout — runtime issue, not loader)
- [ ] `@rpath` / `@executable_path` / `@loader_path` resolution
- [ ] Code signature parsing (`LC_CODE_SIGNATURE`)
- [ ] Deep argument translation: sigprocmask (sigset_t layout), fcntl F_GETLK (struct flock)

## Phase 3 — Runtime Compatibility & dyld (in progress)

**Goal:** Get real macOS CLI tools to run past initialization and produce output.

**Achievements so far:**
- [x] jq 1.7.1 `--version` outputs `jq-1.7.1` on Linux ✅
- [x] jq 1.7.1 `--help` exits cleanly ✅
- [x] **jq 1.7.1 full JSON processing works** ✅ (new in this commit)
  - Tested: field access, array indexing, list comprehension, arithmetic,
    length, keys, map, recursive descent, select, sort, unique, string
    operations (split/join), group_by, file input, filter & map, reduce
- [x] **Fixed chained fixups chain-following** — replaced the broken dual-chain
      approach with proper single-chain walking using correct Apple bit layout:
      - `bind` flag at bit 63 (was already correct)
      - `next` at bits 51-62 with stride 4 (was bits 48-59 with stride 1)
      - `target` at bits 0-42 (43 bits) (was bits 0-35, 36 bits)
      - `high8` at bits 43-50 (was bits 36-43)
      - Bind ordinal is 0-based (ordinal N → import[N])
- [x] Self-contained pthread TLS (pthread_key_create/setspecific/getspecific/once)
- [x] macOS `PTHREAD_ONCE_INIT` magic value (0x30B1BCBA) handling
- [x] `_DefaultRuneLocale` character classification table
- [x] `__maskrune` / `__isctype` functions
- [x] `atexit` / `exit` dynamic symbols (glibc inlines these)
- [x] Math aliases (`__exp10`, `__pow`, etc.)

**Remaining:**
- [ ] ripgrep: still crashes in Rust runtime TLV initialization
      (separate runtime issue, not a fixup issue)
- [ ] `@rpath` / `@executable_path` / `@loader_path` resolution
- [ ] Framework bundle loading (`.framework` directories)
- [ ] On-demand `dyld_stub_binder`

## Phase 4 — Foundation Layer (4-6 weeks)

**Goal:** Apps that use Foundation / CoreFoundation / RunLoop work.

- [ ] Vendor Swift CoreLibs Foundation (Apache 2.0 licensed by Apple)
- [ ] Vendor libdispatch (Apache 2.0)
- [ ] Bridge ObjC runtime needs to GNUstep's libobjc2 or Swift runtime
- [ ] Implement `CFRunLoop` on top of GLib MainContext
- [ ] Property list (`Info.plist`) parser (use Swift CoreLibs')
- [ ] JSON / Property List serialization

**Success criteria:** A macOS CLI tool that uses `URLSession` to fetch JSON works on Linux.

## Phase 5 — AppKit on GTK4 (10-14 weeks, the big one)

**Goal:** Simple AppKit-based GUI apps run.

- [ ] `NSApplication` → `GtkApplication`
- [ ] `NSWindow` → `GtkWindow`
- [ ] `NSView` hierarchy → GTK4 widget tree
- [ ] `NSGraphicsContext` → Cairo/Skia via `GtkSnapshot`
- [ ] CoreGraphics (`CGContext`, paths, gradients) → Cairo
- [ ] CoreText (`CTFont`, `CTLine`) → Pango/HarfBuzz
- [ ] CoreImage → a subset on top of Cairo/Pixman
- [ ] Event translation: NSEvent ← GDK events
- [ ] RunLoop ↔ GLib MainContext integration

**Success criteria:** A small macOS menubar app (e.g. a calculator) runs as a GTK4 window on Linux.

## Phase 6 — Metal on Vulkan (6-10 weeks)

**Goal:** Metal-using games and pro apps render.

- [ ] `MTLDevice` → Vulkan physical device
- [ ] `MTLCommandQueue` / `MTLCommandBuffer` → Vulkan command pools/buffers
- [ ] `MTLRenderPipelineState` → Vulkan graphics pipeline
- [ ] Shaders: `MTLLibrary` (MTL bytecode) → SPIR-V (via a translator, possibly reusing MoltenVK's reverse work)
- [ ] Swapchain integration with GTK4's Vulkan backend

**Success criteria:** A trivial Metal "spinning cube" demo renders on Linux.

## Phase 7 — Static Lifter for Difficult Binaries (8 weeks, parallel)

**Goal:** Binaries that don't load cleanly via dynamic path still work.

- [ ] Mach-O → LLVM IR via McSema or custom pass
- [ ] Re-link against Mac-ify's framework shims at compile time
- [ ] Syscall number rewrite at IR level (no runtime patching needed for these)
- [ ] Caching: lifted ELF is cached at `~/.macify/cache/<hash>.elf`

**Success criteria:** A binary with hand-written assembly that breaks the dynamic loader works via the static lifter.

## Phase 8 — Distribution & UX (3-4 weeks)

- [ ] `macify install Foo.app` → `~/.macify/apps/Foo.app`
- [ ] `macify list`, `macify run Foo`, `macify uninstall Foo`
- [ ] Desktop entries: `.desktop` files generated from `Info.plist`
- [ ] File associations: macOS UTI → Linux MIME type mapping
- [ ] `macify doctor` — diagnose common issues
- [ ] Tier overrides per-app: `macify run --tier=vm Foo.app`

## Phase 9 — Tier-3 VM Fallback (later, optional)

- [ ] QEMU + macOS guest (KVM-accelerated)
- [ ] virtio-gpu for window surfacing
- [ ] virtio-fs for shared `~/Documents`
- [ ] Wayland proxy: macOS windows appear as native Wayland surfaces
- [ ] Clipboard, drag-and-drop, notifications pass-through

## Out of Scope (won't do)

- **Rosetta-style cross-arch emulation.** Running x86_64 macOS on ARM64 Linux (or vice versa) needs a CPU emulator. That's a separate project.
- **Bundling Apple's framework binaries.** Mac-ify ships only its own re-implementations, ever.
- **Code signing evasion.** Apps that check their own signature for DRM will not work. We don't bypass DRM.
- **iOS apps.** Different ABI, different runtime, different sandbox. Not in scope.

## How to Contribute to a Phase

Each phase has a checklist above. Pick an unchecked item, open an issue saying you're working on it, and send a PR. The test suite must pass before merge. New framework re-implementations must include at least one app that exercises them.
