# XNU & Apple Upstream References

Upstream sources used as ground truth for the translation tables in
`src/syscall/` and the shim's pthread handling. Cited per source with
what each one settles. Links verified live at time of writing.

## Sources

### bsd/kern/syscalls.master (xnu)

- Repo: <https://github.com/apple-oss-distributions/xnu>
- Raw: <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/syscalls.master>

Ground truth for every BSD syscall number. The `SYS_*` constants in
`bsd/sys/syscall.h` are generated from this master file by
`bsd/kern/makesyscalls.sh`, so the master file itself is the citable
source (the generated header is not committed to the repo).

What it settled:

- The previous table contained a phantom "modern macOS" block (BSD
  460–501) mapping numbers that do not exist. Real 463 is `openat`,
  which had been routed to `rt_sigprocmask`.
- Corrected entries: 41 `dup`, 82 `setpgid`, 83 `setitimer`,
  86 `getitimer`, 90 `dup2`, 96 `setpriority`, 100 `getpriority`,
  122 `settimeofday`, 126 `setreuid`, 153/154 `pread`/`pwrite`,
  202 `sysctl`. There is **no** BSD `nanosleep`; libc implements it
  over `__semwait_signal` (334).
- Removed phantoms at 331/333 (`__disable_threadsignal`,
  `__pthread_canceled`) that had been mapped to Linux `fchown`/`fchmod`
  and would have executed those with garbage arguments during pthread
  cancellation.
- The xattr family lives at 234–241, not 220–228 (those are
  `getattrlist` and friends). Not yet mapped: macOS xattr calls take
  extra position/options arguments.

### bsd/sys/fcntl.h (xnu)

- Raw: <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/fcntl.h>

Ground truth for macOS-specific fcntl commands. Settled: `F_RDADVISE`
is 44 and `F_RDAHEAD` is 45 (an older comment here claimed 57/58);
also `F_NOCACHE`=48, `F_GETPATH`=50, `F_FULLFSYNC`=51,
`F_GLOBAL_NOCACHE`=55, `F_SETNOSIGPIPE`=73, `F_GETNOSIGPIPE`=74.

### apple-oss-distributions/libpthread

- Repo: <https://github.com/apple-oss-distributions/libpthread>

Home of the userspace pthread implementation. The mutex/cond/rwlock
signature constants are internal ABI and do not appear in its public
OSS headers; the mutex values are documented here empirically, read
from shipped macOS dylibs (`llvm-nm` plus raw byte inspection):

| object            | runtime sig | static-init sig |
|-------------------|-------------|-----------------|
| `pthread_mutex_t` | `0x32AAABA7`| `0x32AAABA2`    |

Cond/rwlock variants: see `shim/pthread/pthread_internal.h`.

What it settled: the interactive-shell deadlock. gettext's statically
initialized `_nl_state_lock` carries the `_init` signature variant;
when `convert_macos_mutex()` recognized only the runtime variant, glibc
locked the raw macOS layout (`__lock = 0x32aaaba2 != 0`), took the
contended path, and waited forever in `futex(val=2)` before bash ever
printed a prompt.

## Re-verifying an entry

```sh
curl -s \
  https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/syscalls.master \
  | grep -E '^\s*463\s+AUE'
# expect: openat
```

For pinning against drift, replace `main` with a release tag such as
`xnu-11215`. See also [`docs/Translation.md`](../Translation.md) for how
these numbers flow into `src/syscall/syscall_table.c`.
