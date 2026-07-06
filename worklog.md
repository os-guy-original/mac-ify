# Macify Project Worklog

## Session Goal
Get `rclone_macos` (a macOS Go binary) to run on Linux via the macify translation layer. Specifically, `./build/macify tests/real/rclone_macos version` should print the rclone version.

## Key Fixes Made This Session

### 1. Per-thread TLS for Go's g pointer (`shim/shim_pthread.c`)
**Problem:** Go stores the current goroutine pointer (g) at `gs:0x30` (TLS). Our `setup_gs_base` set GS base so that `gs:0x30` returns a GLOBAL variable (`g_tls_g_addr`). When a new thread's `crosscall1` wrote the new g pointer to `gs:0x30`, it OVERWROTE the global, corrupting the main thread's view of g. This caused race conditions on `m0.locks` → "runtime·lock: lock count" panic.

**Fix:** In `thread_start_wrapper`, allocate a per-thread 0x100-byte TLS area via mmap and set the new thread's GS base to point to it. Now each thread has its own `gs:0x30` slot.

### 2. `pthread_get_stacksize_np` / `pthread_get_stackaddr_np` main-thread detection (`shim/shim_pthread.c`)
**Problem:** These functions checked `thread == pthread_self()` to detect the main thread, but this is true for ANY thread calling with its own pthread_t. So all threads got the main thread's 64MB stack info, causing new threads' g0.stack to have wrong bounds → stack overflow.

**Fix:** Record the main thread's pthread_t in `__macify_set_stack_info()` and use `pthread_equal()` to properly detect the main thread.

### 3. SIGILL handler installation (`shim/shim_signal.c`)
**Problem:** Our sigaction override blocked SIGILL handler installation for ALL callers, including macify's own `sigaction(SIGILL, sigill_handler, ...)`. Without the SIGILL handler, syscall translation (UD2 → SIGILL) broke.

**Fix:** Only block SIGILL installation from macOS binary callers (check `macify_caller_is_macos_text`). macify's own call goes through normally.

### 4. kqueue/kevent stub implementation (`shim/misc/misc.c`)
**Problem:** Go's runtime on darwin uses kqueue for network polling (netpoll). If kqueue fails, Go throws "runtime: netpollinit failed". Our old stub returned -1 with ENOSYS, which Go treated as fatal.

**Fix:** Implement kqueue() backed by epoll_create1 (returns a real fd). Implement kevent() as a minimal stub that returns 0 (success) for changelist operations. Clear the carry flag (`clc`) before return — Go's runtime may check it.

### 5. `go_is_ready` gsignal offset (`shim/shim_signal.c`)
**Problem:** `go_is_ready()` checked `m+0xb8` for gsignal, but Go 1.24's m struct has gsignal at `m+0x48`. The value at `m+0xb8` is `libcallg` (a different field), causing premature "ready" detection.

**Fix:** Use `m+0x48` for gsignal.

### 6. `macify_go_signal_wrapper` sigset handling (`shim/shim_signal.c`)
**Problem:** Used our overridden `sigemptyset`/`sigaddset` (which write only 4 bytes) but passed the result to glibc's `sigprocmask` (which reads 128 bytes) — 124 bytes were uninitialized garbage.

**Fix:** Use `memset(&mask, 0, sizeof(mask))` and the real glibc `sigaddset`/`sigprocmask` via dlsym.

## Current State (Latest)
Go's runtime FULLY INITIALIZES! The binary gets through:
- rt0_go (entry point, GS base setup)
- cgo_init (C runtime initialization)
- runtime.check (internal consistency checks)
- runtime.args (argument processing)
- runtime.osinit (OS-specific init, sysctl)
- runtime.schedinit (scheduler initialization)
- runtime.newproc (create main goroutine)
- runtime.mstart (start machine/thread)
- kqueue/kevent (network polling)
- pthread_sigmask (signal mask setup)
- sigaltstack (signal stack setup)
- mlock (memory locking)

The crash is now in rclone's APPLICATION CODE (Azure SDK package init),
NOT in Go's runtime initialization. The crash is at adr=0x111 (Go's
intentional crash after a failed check), accessing a corrupted struct
(m pointer = 0x81, which is invalid).

## Fixes Applied This Session

### 1. SA_* flag translation (macOS → Linux)
macOS and Linux use completely different bit values for SA_* flags.
- macOS: SA_ONSTACK=0x0001, SA_SIGINFO=0x0040
- Linux: SA_ONSTACK=0x08000000, SA_SIGINFO=0x00000004
Without translation, signal handlers had wrong flags (no SA_ONSTACK, no SA_SIGINFO).

### 2. pthread_kill signal number translation
Go calls pthread_kill(thread, 16) for SIGURG (macOS #16), but Linux #16
is SIGSTKFLT. Added override to translate macOS signal numbers to Linux.

### 3. real_dlsym initialization
real_dlsym was NULL because the dlsym override wasn't being called (glibc's
dlsym found first in symbol search order). Added macify_init_real_dlsym()
called from constructor.

### 4. sigaction pass-through for non-macOS callers
sigaction override was treating ALL callers as macOS callers, even macify's
own code. This caused Linux-format struct sigaction to be misinterpreted as
macOS-format, reading wrong flags/mask fields. Fixed by passing through
directly for non-macOS callers.

### 5. sigsetsize = 8 (not sizeof(sigset_t) = 128)
Raw rt_sigaction/rt_sigprocmask syscalls passed sizeof(sigset_t)=128 as
sigsetsize, but kernel expects 8. This caused EINVAL, making Go crash.

### 6. pthread_sigmask/sigprocmask infinite recursion
dlsym(RTLD_NEXT, "pthread_sigmask") returned our own function (via dlsym
override), causing infinite recursion. Fixed by using raw rt_sigprocmask
syscall (14).

### 7. SA_RESTORER with custom restorer function
Created macify_restore_rt() function that calls rt_sigreturn syscall.
Used as sa_restorer for all signal handlers installed via raw syscall.

### 8. Raw syscalls for sigaction/sigaltstack
Replaced all real_sigaction/real_sigaltstack calls with raw syscalls
(13 and 131) because real_dlsym(RTLD_NEXT, ...) couldn't find glibc's
versions (glibc loaded before shim).

### 9. mlock/munlock overrides
Go's runtime calls mlock to lock signal stack pages. On Linux without
CAP_IPC_LOCK, mlock fails, causing Go to crash. Override to return 0.

### 10. wrgsbase causes crashes on kernel 5.10
Using wrgsbase to set GS base causes rip=0 (NULL function pointer) crashes
on kernel 5.10. Using only arch_prctl(ARCH_SET_GS) avoids the issue.

## MILESTONE: rclone_macos works on Linux!

`rclone version`, `rclone help`, `rclone --version`, `rclone listremotes`,
`rclone config show`, `rclone config file`, `rclone rc --help`, `rclone mkdir --help`
all work correctly with exit code 0.

### Final Fix
The key breakthrough was setting `GODEBUG=asyncpreemptoff=1` and `GOMAXPROCS=1`
BEFORE `setup_stack`, and using `environ` (not `envp`) in the `setup_stack` call.
Go reads these env vars during `runtime.schedinit` from the `envp` array passed
to `main()`. If they're set after `setup_stack` copies the env strings, Go
doesn't see them.

### Workarounds for kernel 5.10
1. **GODEBUG=asyncpreemptoff=1**: Disables async preemption (SIGURG-based).
   Go's sigtrampgo signal handler crashes when accessing g.m via gs:0x30
   through our signal translation layer.

2. **GOMAXPROCS=1**: Limits Go to one OS thread. Multi-threaded execution
   crashes due to per-thread GS base management issues (each thread's GS base
   must point to its own TLS area, but the kernel's signal delivery on 5.10
   doesn't reliably preserve per-thread GS base).

Both workarounds are acceptable for CLI tools like rclone — they don't need
multi-threaded performance or async preemption for basic commands.
