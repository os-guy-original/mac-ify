# Code Revamp Plan: File Splitting and Reorganization

## Current State

The codebase has grown to ~12,000 lines across 24 files. Several files have
grown too large and need to be split for maintainability.

### Files Needing Split (by size)

| File | Lines | Issue |
|------|-------|-------|
| `shim/shim_signal.c` | 1321 | Signal handling + sigaction + sigset + pthread_kill + Go wrapper + crash handler all in one file |
| `src/syscall.c` | 1241 | Syscall table + SIGILL handler + crash handler + flag translation all in one file |
| `shim/misc/misc.c` | 1167 | kqueue + dispatch + getcontext + ucontext + mlock + random + 20+ unrelated stubs |
| `shim/shim_pthread.c` | 1128 | pthread mutex/cond/rwlock + attr + TLS + pthread_create + pthread_kill + stack info |
| `shim/io/net.c` | 835 | Socket + connect + bind + listen + accept + send/recv + getaddrinfo + DNS all in one |
| `src/main.c` | 662 | Argument parsing + segment loading + fixups + binding + execution all in one |
| `src/fixups.c` | 603 | Old-style binds + chained fixups + weak binds all in one |
| `shim/misc/cf.c` | 558 | CoreFoundation types (CFString, CFArray, CFDictionary, CFNumber, etc.) |
| `shim/shim_mach.c` | 491 | Mach API (host_info, processor_info, vm_info, task_info) |
| `shim/io/file.c` | 395 | stat/lstat/fstat + fstatat + passwd + access + realpath + getcwd + isatty + ioctl |

## Proposed Directory Structure

```
shim/
├── shim.h                          # Main header (keep)
├── core/
│   ├── shim_core.c                 # Constructor, __error, _NSGetArgc/Argv/Environ/ExecPath
│   ├── shim_tlv.c                  # Thread-local variables (keep as-is)
│   └── shim_init.c                 # macify_init_real_dlsym, macify_init_stdio
├── signal/
│   ├── shim_signal.c               # sigaction/signal/sigaltstack overrides
│   ├── sigset.c                    # sigaddset/sigdelset/sigemptyset/sigfillset/sigismember
│   ├── sigmask.c                   # pthread_sigmask/sigprocmask
│   ├── crash_handler.c             # macify_crash_handler + Go state printing
│   ├── go_signal.c                 # macify_go_signal_wrapper, go_is_ready
│   └── restorer.c                  # macify_restore_rt (SA_RESTORER)
├── pthread/
│   ├── mutex.c                     # pthread_mutex_lock/unlock/trylock/init/destroy
│   ├── cond.c                      # pthread_cond_wait/signal/broadcast/init/destroy
│   ├── rwlock.c                    # pthread_rwlock_rdlock/wrlock/unlock/init/destroy
│   ├── attr.c                      # pthread_attr_init/destroy/setstacksize/getstacksize
│   ├── create.c                    # pthread_create + thread_start_wrapper
│   ├── kill.c                      # pthread_kill (signal number translation)
│   ├── stack.c                     # pthread_get_stackaddr_np/get_stacksize_np
│   ├── tls.c                       # pthread_key_create/getspecific/setspecific
│   └── setname.c                   # pthread_setname_np/getname_np
├── io/
│   ├── open.c                      # open/openat + flag translation
│   ├── stat.c                      # stat/lstat/fstat/fstatat + macos_stat struct
│   ├── file.c                      # access/realpath/getcwd/isatty/ioctl
│   ├── read.c                      # read/write/readv/writev (pipe handling)
│   ├── dir.c                       # opendir/readdir/closedir/dirfd
│   ├── mmap.c                      # mmap/munmap/mprotect/madvise
│   ├── fcntl.c                     # fcntl
│   ├── passwd.c                    # getpwuid/getpwuid_r/getpwnam
│   └── dl.c                        # dlopen/dlsym/dlclose + macify_get_shim_symbol
├── net/
│   ├── socket.c                    # socket/connect/bind/listen/accept
│   ├── sendrecv.c                  # send/recv/sendto/recvfrom/sendmsg/recvmsg
│   ├── addrinfo.c                  # getaddrinfo/freeaddrinfo/getnameinfo
│   └── dns.c                       # DNS resolution stubs
├── mach/
│   ├── shim_mach.c                 # Mach host_info/processor_info/vm_info
│   └── semaphore.c                 # Mach semaphore stubs
├── cf/
│   ├── cf_string.c                 # CFString functions
│   ├── cf_array.c                  # CFArray functions
│   ├── cf_dict.c                   # CFDictionary functions
│   ├── cf_number.c                 # CFNumber functions
│   ├── cf_date.c                   # CFDate functions
│   ├── cf_data.c                   # CFData functions
│   ├── cf_url.c                    # CFURL functions
│   ├── cf_error.c                  # CFError functions
│   ├── cf_bundle.c                 # CFBundle functions
│   ├── cf_timezone.c               # CFTimeZone functions
│   ├── cf_property.c               # CFPropertyList functions
│   └── cf_compat.c                 # CF compatibility stubs (keep as-is)
├── objc/
│   ├── shim_objc.c                 # Objective-C runtime stubs (keep as-is)
│   └── objc_compat.c               # ObjC compatibility (keep as-is)
├── spawn/
│   └── shim_spawn.c                # posix_spawn/posix_spawnp (keep as-is)
├── sys/
│   ├── sysctl.c                    # sysctl/sysctlbyname/sysctlnametomib
│   ├── kqueue.c                    # kqueue/kevent
│   ├── dispatch.c                  # dispatch_semaphore/once/async/sync
│   ├── ucontext.c                  # getcontext/setcontext/makecontext
│   ├── mlock.c                     # mlock/munlock/mlockall/munlockall
│   ├── random.c                    # srandomdev/arc4random
│   └── misc_stubs.c                # Remaining small stubs
└── string/
    ├── rune.c                      # Rune locale (keep as-is)
    └── string.c                    # String compat (keep as-is)

src/
├── main.c                          # Entry point, argument parsing (slim down)
├── runtime.c                       # Stack setup, GS base, entry jump (keep as-is)
├── loader/
│   ├── segments.c                  # Segment loading, memory mapping
│   ├── fixups.c                    # Old-style bind bytecode execution
│   ├── chained_fixups.c            # DYLD chained fixups
│   └── symbols.c                   # resolve_symbol + symbol resolution
├── syscall/
│   ├── syscall_table.c             # BSD→Linux syscall number table
│   ├── sigill_handler.c            # SIGILL slow-path handler
│   ├── crash_handler.c             # crash_handler for SIGSEGV/SIGBUS
│   ├── flag_translation.c          # open/mmap/kill/fcntl flag translation
│   └── syscall_names.c             # BSD syscall name lookup
├── patch/
│   ├── syscall_patcher.c           # Patch syscall instructions in text
│   └── systemstack_patcher.c       # Patch Go systemstack trampolines
└── macify.h                        # Main header (keep)
```

## Splitting Priority

### Phase 1: Highest Impact (files > 1000 lines)

1. **`shim/shim_signal.c` → `shim/signal/`**
   - `shim_signal.c` (sigaction/signal/sigaltstack) ~400 lines
   - `sigset.c` (sigaddset/sigdelset/sigemptyset/sigfillset/sigismember) ~80 lines
   - `sigmask.c` (pthread_sigmask/sigprocmask) ~100 lines
   - `crash_handler.c` (macify_crash_handler) ~200 lines
   - `go_signal.c` (macify_go_signal_wrapper, go_is_ready) ~80 lines
   - `restorer.c` (macify_restore_rt) ~20 lines

2. **`src/syscall.c` → `src/syscall/`**
   - `syscall_table.c` (bsd_to_linux table + arg flags) ~200 lines
   - `sigill_handler.c` (SIGILL slow-path handler) ~400 lines
   - `crash_handler.c` (crash_handler for SIGSEGV) ~100 lines
   - `flag_translation.c` (open/mmap/kill/fcntl/sigaltstack translation) ~200 lines
   - `syscall_names.c` (bsd_syscall_name) ~100 lines

3. **`shim/misc/misc.c` → `shim/sys/`**
   - `kqueue.c` (kqueue/kevent) ~60 lines
   - `dispatch.c` (dispatch_semaphore/once/async/sync) ~100 lines
   - `ucontext.c` (getcontext/setcontext/makecontext) ~80 lines
   - `mlock.c` (mlock/munlock/mlockall/munlockall) ~30 lines
   - `random.c` (srandomdev/arc4random) ~30 lines
   - `misc_stubs.c` (remaining stubs) ~100 lines

4. **`shim/shim_pthread.c` → `shim/pthread/`**
   - `mutex.c` ~100 lines
   - `cond.c` ~80 lines
   - `rwlock.c` ~50 lines
   - `attr.c` ~80 lines
   - `create.c` (pthread_create + thread_start_wrapper) ~120 lines
   - `kill.c` (pthread_kill) ~20 lines
   - `stack.c` (pthread_get_stackaddr_np/stacksize_np) ~50 lines
   - `tls.c` ~120 lines
   - `setname.c` ~30 lines

### Phase 2: Medium Impact (files 500-1000 lines)

5. **`shim/io/net.c` → `shim/net/`**
   - `socket.c` (socket/connect/bind/listen/accept) ~200 lines
   - `sendrecv.c` (send/recv/sendto/recvfrom/sendmsg/recvmsg) ~200 lines
   - `addrinfo.c` (getaddrinfo/freeaddrinfo/getnameinfo) ~200 lines
   - `dns.c` (DNS stubs) ~100 lines

6. **`src/main.c` → slim down + `src/loader/`**
   - Keep argument parsing and orchestration in `main.c` (~200 lines)
   - Move segment loading to `loader/segments.c`
   - Move symbol resolution to `loader/symbols.c`

7. **`src/fixups.c` → `src/loader/`**
   - `fixups.c` (old-style binds) ~300 lines
   - `chained_fixups.c` (DYLD chained fixups) ~300 lines

8. **`shim/misc/cf.c` → `shim/cf/`**
   - Split by CFType (CFString, CFArray, CFDictionary, etc.)

### Phase 3: Lower Impact (files 300-500 lines)

9. **`shim/io/file.c` → `shim/io/`**
   - `stat.c` (stat/lstat/fstat/fstatat + macos_stat)
   - `file.c` (access/realpath/getcwd/isatty/ioctl)
   - `passwd.c` (getpwuid/getpwuid_r/getpwnam)

10. **`shim/shim_mach.c` → `shim/mach/`**
    - Keep as single file or split host_info/processor_info

## Implementation Guidelines

1. **One split at a time**: Each split should be a separate commit. Build and
   test all binaries after each split.

2. **Shared headers**: Each subdirectory gets its own internal header:
   - `shim/signal/signal_internal.h`
   - `shim/pthread/pthread_internal.h`
   - `shim/io/io_internal.h` (already exists)
   - `src/loader/loader_internal.h`
   - `src/syscall/syscall_internal.h`

3. **No functional changes**: The split should be pure code movement. No logic
   changes, no refactoring — just moving functions to new files.

4. **Update Makefiles**: Each subdirectory gets its own Makefile fragment or
   the main Makefile is updated to glob source files from subdirectories.

5. **Test after each split**: Run all test binaries to verify nothing broke:
   ```bash
   for bin in jq_darwin tree_macos sqlite3_macos rg_macos fd_macos sd_macos \
              grep_macos gzip_macos rclone_macos less_macos nano_macos htop_macos; do
     LD_LIBRARY_PATH=build ./build/macify -q tests/real/$bin --version 2>/dev/null | head -1
   done
   ```

## Benefits

- **Faster compilation**: Only changed files need recompilation
- **Easier navigation**: Find functions by directory, not by searching a 1300-line file
- **Clearer ownership**: Each file has a single responsibility
- **Better diffs**: PRs touch smaller, more focused files
- **Easier testing**: Can unit-test individual modules
