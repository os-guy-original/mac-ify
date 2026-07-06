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

## Current State
- Binary gets past: rt0_go, cgo_init, runtime.check, runtime.args, runtime.osinit, runtime.schedinit, runtime.newproc, runtime.mstart
- Binary creates new threads via pthread_create (multiple threads, each with per-thread TLS)
- kqueue() succeeds (returns epoll fd)
- kevent() succeeds for changelist operations (EVFILT_USER setup, adding fds)
- kevent() with nevents > 0 returns 0 (no events)
- Now crashing with SIGSEGV at adr=0, rip in glibc's futex wrapper (FUTEX_WAKE)
- m.locks = 2 (positive, no lock count issue)
- No stack overflow
- Crash is on the main thread's g0/systemstack
- The crash appears to be a signal delivery issue (SIGSEGV at adr=0 with rip at a non-memory-accessing instruction)

## Next Steps
- The crash is at glibc's futex wrapper, AFTER the syscall. The `cmp` instruction at rip doesn't access memory, so the SIGSEGV is likely from signal delivery (kernel trying to deliver a signal and failing).
- Possible causes:
  1. Go's runtime sets up a signal stack via a path we don't intercept
  2. The signal stack is being corrupted
  3. Go's runtime is in a bad state due to our kqueue/kevent stubs not behaving correctly
- Try: implement a more complete kqueue/kevent emulation (using epoll actually)
- Try: check if Go's runtime expects kevent to block (return only after events arrive)
- Try: trace ALL signals to see what's being delivered
