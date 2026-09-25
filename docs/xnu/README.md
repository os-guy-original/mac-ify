# XNU & Apple Upstream References

Upstream sources used as ground truth for the translation tables in
`src/syscall/` and the shim's pthread handling. Cited per source with
what each one settles. Links verified live at time of writing.

### bsd/sys/termios.h (xnu)

- Raw: <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/termios.h>
- Local copy: [`headers/sys_termios.h`](headers/sys_termios.h)

Ground truth for struct termios layout, flag bits, c_cc indices, and
speed constants. Settled:

- `c_cc` indices (NCCS=20): VEOF=0 VEOL=1 VEOL2=2 VERASE=3 VWERASE=4
  VKILL=5 VREPRINT=6 VINTR=8 VQUIT=9 VSUSP=10 VDSUSP=11 VSTART=12
  VSTOP=13 VLNEXT=14 VDISCARD=15 VMIN=16 VTIME=17 VSTATUS=18.
  Darwin c_cc slots 7/11/19 are spare — VDSUSP=11 exists (IEXTEN) and
  is distinct from Linux VSWTC=7.
- Flag bits: macOS ICANON=0x100/ISIG=0x80 (Linux 0x2/0x1), macOS
  ONLCR=0x2 (Linux 0x4), macOS OXTABS=0x4 ≈ Linux TABDLY/TAB3=0xc00,
  **OFDEL=0x20000 on macOS vs 0x80 on Linux** (an older table assumed
  0x100, which is VTDLY on macOS — the round trip corrupted the bit).
- Darwin `c_cflag` carries no CBAUD field; speeds live only in
  c_ispeed/c_ospeed as literal rates (B57600=57600 … B230400=230400;
  B76800 exists on macOS with no Linux kernel-code equivalent).
- TCSANOW/DRAIN/FLUSH = 0/1/2 on both systems; macOS additionally has
  TCSASOFT=0x10 (dropped in translation).

### bsd/sys/signal.h, bsd/sys/errno.h (xnu)

- Raw: <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/signal.h>
  and `.../errno.h` · Local copies: [`headers/sys_signal.h`](headers/sys_signal.h),
  [`headers/sys_errno.h`](headers/sys_errno.h)

Signal numbers (SIGHUP=1 … SIGUSR2=31; SIGEMT=7, SIGINFO=29 — the
 untranslated-passthrough collisions flagged in AUDIT) and the full
errno ordering (1..110, EAGAIN=35, EINPROGRESS=36, EDEADLK=11) used by
the shim errno table.

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
