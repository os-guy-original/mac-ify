#include "macify.h"

/* Syscall translation table — flat array indexed by BSD syscall #.
 * macOS x86_64 syscall numbers: 0x2000000 | BSD_NR, where BSD_NR is 0..~500
 * for the syscalls we care about. Each entry is the Linux syscall number,
 * or -1 if unimplemented. Argument translation flags live in a parallel
 * array.
 */

#define BSD_SYSCALL_MAX 600

static const int16_t bsd_to_linux[BSD_SYSCALL_MAX] = {
    /* [0] is unused */
    [1]   = 231,            /* exit           -> exit_group (kills all threads) */
    [2]   = SYS_fork,       /* fork           */
    [3]   = SYS_read,       /* read           */
    [4]   = SYS_write,      /* write          */
    [5]   = SYS_open,       /* open           (ARG_OPEN_FLAGS) */
    [6]   = SYS_close,      /* close          */
    [7]   = SYS_wait4,      /* wait4          */
    [9]   = SYS_link,       /* link           */
    [10]  = SYS_unlink,     /* unlink         */
    [12]  = SYS_chdir,      /* chdir          */
    [13]  = SYS_fchdir,     /* fchdir         */
    [14]  = SYS_mknod,      /* mknod          */
    [15]  = SYS_chmod,      /* chmod          */
    [16]  = SYS_chown,      /* chown          */
    [20]  = SYS_getpid,     /* getpid         */
    [23]  = SYS_setuid,     /* setuid         */
    [24]  = SYS_getuid,     /* getuid         */
    [25]  = SYS_geteuid,    /* geteuid        */
    [27]  = SYS_recvmsg,    /* recvmsg        */
    [28]  = SYS_sendmsg,    /* sendmsg        */
    [29]  = SYS_recvfrom,   /* recvfrom       */
    [30]  = SYS_accept,     /* accept         */
    [31]  = SYS_getpeername,/* getpeername    */
    [32]  = SYS_getsockname,/* getsockname    */
    [33]  = SYS_access,     /* access         */
    [36]  = SYS_sync,       /* sync           */
    [37]  = SYS_kill,       /* kill           */
    [39]  = SYS_getppid,    /* getppid        */
    [41]  = SYS_pipe,       /* pipe (old macOS) */
    [42]  = SYS_pipe,       /* pipe (modern macOS) */
    [43]  = SYS_getegid,    /* getegid        */
    [46]  = SYS_rt_sigaction, /* sigaction (old macOS) */
    [47]  = SYS_getgid,     /* getgid         */
    [48]  = SYS_rt_sigprocmask, /* sigprocmask */
    [53]  = SYS_sigaltstack,/* sigaltstack — struct translated via ARG_SIGALTSTACK */
    [54]  = SYS_ioctl,      /* ioctl          (pass-through) */
    [57]  = SYS_symlink,    /* symlink        */
    [58]  = SYS_readlink,   /* readlink       */
    [59]  = SYS_execve,     /* execve         */
    [60]  = SYS_umask,      /* umask          */
    [61]  = SYS_chroot,     /* chroot         */
    [65]  = SYS_msync,      /* msync          (flags identical) */
    [73]  = SYS_munmap,     /* munmap         */
    [74]  = SYS_mprotect,   /* mprotect       (prot identical) */
    [75]  = SYS_madvise,    /* madvise        */
    [78]  = SYS_mincore,    /* mincore        */
    [79]  = SYS_getgroups,  /* getgroups      */
    [80]  = SYS_setgroups,  /* setgroups      */
    [81]  = SYS_getpgrp,    /* getpgrp        */
    [82]  = SYS_setpriority,/* setpriority    */
    [83]  = SYS_getpriority,/* getpriority    */
    [89]  = SYS_getitimer,  /* getitimer      */
    [90]  = SYS_setitimer,  /* setitimer      */
    [92]  = SYS_fcntl,      /* fcntl          */
    [93]  = SYS_select,     /* select         */
    [95]  = SYS_fsync,      /* fsync          */
    [97]  = SYS_socket,     /* socket         (type identical) */
    [98]  = SYS_connect,    /* connect        */
    [116] = SYS_gettimeofday, /* gettimeofday */
    [117] = SYS_getrusage,  /* getrusage      (struct layout same) */
    [118] = SYS_getsockopt, /* getsockopt     */
    [120] = SYS_readv,      /* readv          */
    [121] = SYS_writev,     /* writev         */
    [126] = SYS_settimeofday, /* settimeofday */
    [128] = SYS_rename,     /* rename         */
    [131] = SYS_flock,      /* flock          (op identical) */
    [133] = SYS_sendto,     /* sendto         */
    [134] = SYS_shutdown,   /* shutdown       (how identical) */
    [135] = SYS_socketpair, /* socketpair     */
    [136] = SYS_mkdir,      /* mkdir          */
    [137] = SYS_rmdir,      /* rmdir          */
    [138] = SYS_utimes,     /* utimes         */
    [197] = SYS_mmap,       /* mmap           (flags translated) */
    [199] = SYS_lseek,      /* lseek          */
    [200] = SYS_truncate,   /* truncate       */
    [201] = SYS_ftruncate,  /* ftruncate      */
    [202] = SYS_nanosleep,  /* nanosleep      */
    [220] = SYS_getxattr,   /* getxattr       */
    [221] = SYS_fgetxattr,  /* fgetxattr      */
    [222] = SYS_setxattr,   /* setxattr       */
    [223] = SYS_fsetxattr,  /* fsetxattr      */
    [224] = SYS_removexattr,/* removexattr    */
    [225] = SYS_fremovexattr,/* fremovexattr  */
    [226] = SYS_listxattr,  /* listxattr      */
    [227] = SYS_llistxattr, /* llistxattr     */
    [228] = SYS_flistxattr, /* flistxattr     */
    [286] = SYS_pwrite64,   /* pwrite (old macOS) */
    [287] = SYS_pread64,    /* pread  (old macOS) */
    [331] = SYS_fchown,     /* fchown         */
    [333] = SYS_fchmod,     /* fchmod         */
    [396] = SYS_read,       /* read_nocancel          */
    [397] = SYS_write,      /* write_nocancel         */
    [398] = SYS_open,       /* open_nocancel (ARG_OPEN_FLAGS) */
    [399] = SYS_close,      /* close_nocancel         */
    [400] = SYS_wait4,      /* wait4_nocancel         */
    [401] = SYS_recvmsg,    /* recvmsg_nocancel       */
    [402] = SYS_sendmsg,    /* sendmsg_nocancel       */
    [403] = SYS_recvfrom,   /* recvfrom_nocancel      */
    [404] = SYS_accept,     /* accept_nocancel        */
    [405] = SYS_fcntl,      /* fcntl_nocancel         */
    [406] = SYS_select,     /* select_nocancel        */
    [460] = SYS_pread64,    /* pread  (modern macOS)  */
    [461] = SYS_pwrite64,   /* pwrite (modern macOS)  */
    [462] = SYS_rt_sigaction, /* sigaction_nocancel (modern macOS) */
    [463] = SYS_rt_sigprocmask, /* sigprocmask_nocancel (modern macOS) */
    [465] = SYS_pread64,    /* pread_nocancel         */
    [466] = SYS_pwrite64,   /* pwrite_nocancel        */
    /* Go binaries use modern macOS syscall numbers (400+) */
    [477] = SYS_mmap,       /* mmap (modern macOS)    (ARG_MMAP_FLAGS) */
    [478] = SYS_lseek,      /* lseek (modern macOS)   */
    [480] = SYS_ftruncate,  /* ftruncate (modern macOS) */
    [481] = SYS_truncate,   /* truncate (modern macOS) */
    [482] = SYS_stat,       /* stat (modern macOS)    */
    [483] = SYS_fstat,      /* fstat (modern macOS)   */
    [484] = SYS_lstat,      /* lstat (modern macOS)   */
    [485] = SYS_unlink,     /* unlink (modern macOS)  */
    [486] = SYS_access,     /* access (modern macOS)  */
    [488] = SYS_read,       /* read_nocancel (modern) */
    [489] = SYS_write,      /* write_nocancel (modern) */
    [490] = SYS_open,       /* open_nocancel (modern) (ARG_OPEN_FLAGS) */
    [491] = SYS_close,      /* close_nocancel (modern) */
    [492] = SYS_getpid,     /* getpid (modern macOS)  */
    [493] = SYS_getuid,     /* getuid (modern macOS)  */
    [494] = SYS_geteuid,    /* geteuid (modern macOS) */
    [495] = SYS_getgid,     /* getgid (modern macOS)  */
    [496] = SYS_getegid,    /* getegid (modern macOS) */
    [497] = SYS_setuid,     /* setuid (modern macOS)  */
    [498] = SYS_setgid,     /* setgid (modern macOS)  */
    [500] = SYS_read,       /* read_nocancel (modern macOS) */
    [501] = SYS_write,      /* write_nocancel (modern macOS) */
    /* All other entries are 0 (unimplemented). We treat 0 as "unimplemented"
     * because Linux syscall 0 is SYS_read, which we never want to dispatch
     * to from a macOS syscall. Use -1 in the table to be explicit. */
};

/* Argument translation flags. */
#define ARG_OPEN_FLAGS    0x01   /* translate macOS open() flag bits */
#define ARG_MMAP_FLAGS    0x02   /* translate mmap() flag bits (MAP_ANON etc) */
#define ARG_FCNTL_CMD     0x04   /* translate fcntl() cmd values */
#define ARG_KILL_SIGNAL   0x08   /* translate kill() signal number */
#define ARG_MADVISE       0x10   /* translate madvise() advice value */
#define ARG_SIGACTION     0x20   /* translate sigaction struct (macOS → Linux) */
#define ARG_SIGPROCMASK   0x40   /* translate sigprocmask sigset_t (4B → 8B) + add sigsetsize arg */
#define ARG_SIGALTSTACK   0x100  /* translate sigaltstack stack_t (field order differs) */
#define ARG_FORCE_SLOW    0x80   /* always go through SIGILL (e.g., exit) */

/* Constants confirmed identical between macOS and Linux (no translation):
 *   PROT_*  (mprotect, mmap prot arg)
 *   SOCK_*  (socket type, except macOS lacks SOCK_CLOEXEC)
 *   LOCK_*  (flock op)
 *   SHUT_*  (shutdown how)
 *   MS_*    (msync flags)
 *   RUSAGE_* (getrusage who; struct rusage layout also same)
 *   SIG_BLOCK/UNBLOCK/SETMASK (sigprocmask how; sigset_t layout differs — deep issue)
 * ioctl cmd values are too complex to translate; passed through as-is.
 */

static const uint8_t bsd_arg_flags[BSD_SYSCALL_MAX] = {
    [1]   = ARG_FORCE_SLOW,                   /* exit — print stats */
    [5]   = ARG_OPEN_FLAGS,                   /* open */
    [37]  = ARG_KILL_SIGNAL,                  /* kill */
    [46]  = ARG_SIGACTION | ARG_FORCE_SLOW,   /* sigaction — struct translation */
    [48]  = ARG_SIGPROCMASK | ARG_FORCE_SLOW, /* sigprocmask — sigset_t translation */
    [53]  = ARG_SIGALTSTACK | ARG_FORCE_SLOW, /* sigaltstack — stack_t field order differs */
    [75]  = ARG_MADVISE,                      /* madvise */
    [92]  = ARG_FCNTL_CMD,                    /* fcntl */
    [197] = ARG_MMAP_FLAGS,                   /* mmap */
    [398] = ARG_OPEN_FLAGS,                   /* open_nocancel */
    [405] = ARG_FCNTL_CMD,                    /* fcntl_nocancel */
    [462] = ARG_SIGACTION | ARG_FORCE_SLOW,   /* sigaction_nocancel — struct translation */
    [463] = ARG_SIGPROCMASK | ARG_FORCE_SLOW, /* sigprocmask_nocancel — sigset_t translation */
    [477] = ARG_MMAP_FLAGS,                   /* mmap (modern macOS) */
    [490] = ARG_OPEN_FLAGS,                   /* open_nocancel (modern macOS) */
    /* wait4 (7) options WCONTINUED bit differs but is rarely used. */
};

/* BSD syscall names for nicer verbose output. */
static const char *bsd_syscall_name(uint32_t bsd_nr) {
    switch (bsd_nr) {
        case 1:   return "exit";
        case 2:   return "fork";
        case 3:   return "read";
        case 4:   return "write";
        case 5:   return "open";
        case 6:   return "close";
        case 7:   return "wait4";
        case 9:   return "link";
        case 10:  return "unlink";
        case 12:  return "chdir";
        case 13:  return "fchdir";
        case 14:  return "mknod";
        case 15:  return "chmod";
        case 16:  return "chown";
        case 20:  return "getpid";
        case 23:  return "setuid";
        case 24:  return "getuid";
        case 25:  return "geteuid";
        case 27:  return "recvmsg";
        case 28:  return "sendmsg";
        case 29:  return "recvfrom";
        case 30:  return "accept";
        case 31:  return "getpeername";
        case 32:  return "getsockname";
        case 33:  return "access";
        case 36:  return "sync";
        case 37:  return "kill";
        case 39:  return "getppid";
        case 41:  return "pipe";
        case 42:  return "pipe";
        case 43:  return "getegid";
        case 46:  return "sigaction";
        case 47:  return "getgid";
        case 48:  return "sigprocmask";
        case 53:  return "sigaltstack";
        case 54:  return "ioctl";
        case 57:  return "symlink";
        case 58:  return "readlink";
        case 59:  return "execve";
        case 60:  return "umask";
        case 61:  return "chroot";
        case 65:  return "msync";
        case 73:  return "munmap";
        case 74:  return "mprotect";
        case 75:  return "madvise";
        case 78:  return "mincore";
        case 79:  return "getgroups";
        case 80:  return "setgroups";
        case 81:  return "getpgrp";
        case 82:  return "setpriority";
        case 83:  return "getpriority";
        case 89:  return "getitimer";
        case 90:  return "setitimer";
        case 92:  return "fcntl";
        case 93:  return "select";
        case 95:  return "fsync";
        case 97:  return "socket";
        case 98:  return "connect";
        case 116: return "gettimeofday";
        case 117: return "getrusage";
        case 118: return "getsockopt";
        case 120: return "readv";
        case 121: return "writev";
        case 126: return "settimeofday";
        case 128: return "rename";
        case 131: return "flock";
        case 133: return "sendto";
        case 134: return "shutdown";
        case 135: return "socketpair";
        case 136: return "mkdir";
        case 137: return "rmdir";
        case 138: return "utimes";
        case 197: return "mmap";
        case 199: return "lseek";
        case 200: return "truncate";
        case 201: return "ftruncate";
        case 202: return "nanosleep";
        case 220: return "getxattr";
        case 221: return "fgetxattr";
        case 222: return "setxattr";
        case 223: return "fsetxattr";
        case 224: return "removexattr";
        case 225: return "fremovexattr";
        case 226: return "listxattr";
        case 227: return "llistxattr";
        case 228: return "flistxattr";
        case 286: return "pwrite";
        case 287: return "pread";
        case 331: return "fchown";
        case 333: return "fchmod";
        case 396: return "read_nocancel";
        case 397: return "write_nocancel";
        case 398: return "open_nocancel";
        case 399: return "close_nocancel";
        case 400: return "wait4_nocancel";
        case 401: return "recvmsg_nocancel";
        case 402: return "sendmsg_nocancel";
        case 403: return "recvfrom_nocancel";
        case 404: return "accept_nocancel";
        case 405: return "fcntl_nocancel";
        case 406: return "select_nocancel";
        case 460: return "pread";
        case 461: return "pwrite";
        case 465: return "pread_nocancel";
        case 466: return "pwrite_nocancel";
        default:  return "?";
    }
}


/* Syscall argument translation
 * 
 * Most syscalls take the same args on macOS and Linux (file
 * descriptors, pointers, sizes). A few take flag bitmasks whose
 * numeric values differ between the two systems.
 */

static int translate_open_flags(int macos_flags) {
    int linux_flags = macos_flags & 0x3;  /* O_RDONLY / O_WRONLY / O_RDWR */
    if (macos_flags & 0x0000004) linux_flags |= O_NONBLOCK;
    if (macos_flags & 0x0000008) linux_flags |= O_APPEND;
    if (macos_flags & 0x0000040) linux_flags |= O_ASYNC;
    if (macos_flags & 0x0000080) linux_flags |= O_SYNC;
    if (macos_flags & 0x0000100) linux_flags |= O_NOFOLLOW;
    if (macos_flags & 0x0000200) linux_flags |= O_CREAT;
    if (macos_flags & 0x0000400) linux_flags |= O_TRUNC;
    if (macos_flags & 0x0000800) linux_flags |= O_EXCL;
    if (macos_flags & 0x0020000) linux_flags |= O_NOCTTY;
    if (macos_flags & 0x1000000) linux_flags |= O_CLOEXEC;
    return linux_flags;
}

/* mmap flags — prot bits are the same, but flag bits differ.
 * macOS MAP_ANON=0x1000 vs Linux MAP_ANONYMOUS=0x20 is the big one. */
static int translate_mmap_flags(int macos_flags) {
    int linux_flags = 0;
    /* Access mode (low 2 bits) — same on both. */
    linux_flags |= macos_flags & 0x3;
    /* Common flags — same bit positions on both. */
    if (macos_flags & 0x0001) linux_flags |= MAP_SHARED;
    if (macos_flags & 0x0002) linux_flags |= MAP_PRIVATE;
    if (macos_flags & 0x0010) linux_flags |= MAP_FIXED;
    /* MAP_ANON (macOS 0x1000) → MAP_ANONYMOUS (Linux 0x20). */
    if (macos_flags & 0x1000) linux_flags |= MAP_ANONYMOUS;
    /* Linux-only flags we can't translate from macOS — ignored. */
    return linux_flags;
}

/* kill() signal number translation.
 * Signals 1-6 are the same. From 7 onward macOS and Linux diverge. */
static int translate_kill_signal(int macos_sig) {
    /* 1=SIGHUP, 2=SIGINT, 3=SIGQUIT, 4=SIGILL, 5=SIGTRAP, 6=SIGABRT,
       9=SIGKILL, 11=SIGSEGV, 13=SIGPIPE, 14=SIGALRM, 15=SIGTERM —
       all the same on macOS and Linux. */
    static const int sig_xlate[32] = {
        [0]  = 0,                /* 0 = no signal (kill(pid, 0) checks existence) */
        [7]  = 0,                /* macOS SIGEMT — no Linux equivalent; 0 = skip */
        [8]  = 8,                /* SIGFPE — same */
        [10] = 7,                /* macOS SIGBUS  → Linux SIGBUS (7) */
        [12] = 31,               /* macOS SIGSYS  → Linux SIGSYS (31) */
        [16] = 23,               /* macOS SIGURG  → Linux SIGURG (23) */
        [17] = 19,               /* macOS SIGSTOP → Linux SIGSTOP (19) */
        [18] = 20,               /* macOS SIGTSTP → Linux SIGTSTP (20) */
        [19] = 18,               /* macOS SIGCONT → Linux SIGCONT (18) */
        [20] = 17,               /* macOS SIGCHLD → Linux SIGCHLD (17) */
        [21] = 21,               /* SIGTTIN — same */
        [22] = 22,               /* SIGTTOU — same */
        [23] = 29,               /* macOS SIGIO   → Linux SIGIO (29) */
        [24] = 24,               /* SIGXCPU — same */
        [25] = 25,               /* SIGXFSZ — same */
        [26] = 26,               /* SIGVTALRM — same */
        [27] = 27,               /* SIGPROF — same */
        [28] = 28,               /* SIGWINCH — same */
        [29] = 0,                /* macOS SIGINFO — no Linux equivalent; 0 = skip */
        [30] = 10,               /* macOS SIGUSR1 → Linux SIGUSR1 (10) */
        [31] = 12,               /* macOS SIGUSR2 → Linux SIGUSR2 (12) */
    };
    if (macos_sig < 0 || macos_sig >= 32) return macos_sig;  /* pass through */
    int linux_sig = sig_xlate[macos_sig];
    return linux_sig ? linux_sig : macos_sig;  /* 0 means "no equiv" → pass through */
}

/* fcntl() cmd translation. Cmds 0-4 are the same. 5-9 are reshuffled. */
static int translate_fcntl_cmd(int macos_cmd) {
    switch (macos_cmd) {
        case 0: return F_DUPFD;            /* same */
        case 1: return F_GETFD;            /* same */
        case 2: return F_SETFD;            /* same */
        case 3: return F_GETFL;            /* same */
        case 4: return F_SETFL;            /* same */
        case 5: return F_GETOWN;           /* macOS F_GETOWN=5, Linux=9 */
        case 6: return F_SETOWN;           /* macOS F_SETOWN=6, Linux=8 */
        case 7: return F_GETLK;            /* macOS F_GETLK=7,  Linux=5 */
        case 8: return F_SETLK;            /* macOS F_SETLK=8,  Linux=6 */
        case 9: return F_SETLKW;           /* macOS F_SETLKW=9, Linux=7 */
        case 67: return F_DUPFD_CLOEXEC;   /* macOS 67, Linux 1030 */
        /* macOS-specific cmds (F_GETPATH=50, F_FULLFSYNC=51, F_NOCACHE=48,
         * F_RDADVISE=57, F_RDAHEAD=58, F_PREALLOCATE=42, etc.) have no
         * Linux equivalent. Return -1 to signal "unsupported". */
        default: return -1;
    }
}

/* madvise() advice translation. 0-4 are the same. MADV_FREE differs. */
static int translate_madvise(int macos_advice) {
    switch (macos_advice) {
        case 0: return MADV_NORMAL;       /* same */
        case 1: return MADV_RANDOM;       /* same */
        case 2: return MADV_SEQUENTIAL;   /* same */
        case 3: return MADV_WILLNEED;     /* same */
        case 4: return MADV_DONTNEED;     /* same */
        case 5: return MADV_FREE;         /* macOS MADV_FREE=5, Linux=8 */
        /* macOS-specific (MADV_ZERO_WIRED_PAGES=6, MADV_FREE_REUSABLE=7,
         * MADV_FREE_REUSE=8, MADV_CAN_REUSE=9) — no Linux equivalent.
         * Fall through to default. */
        default: return macos_advice;     /* pass through; Linux may reject */
    }
}


/* Raw syscall — bypasses glibc's errno translation. */

static inline long raw_syscall(long nr, long a1, long a2, long a3,
                                long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}


/* Stats printing */

void print_stats(void) {
    if (g_stats_printed) return;
    g_stats_printed = true;
    fprintf(stderr, "\nmacify: stats:\n");
    fprintf(stderr, "         slow-path SIGILL invocations: %lu\n", g_slow_path_calls);
    fprintf(stderr, "         fast-path syscall sites:      %lu  (patched at load)\n",
            g_fast_path_sites);
    fprintf(stderr, "         slow-path syscall sites:      %lu  (patched at load)\n",
            g_slow_path_sites);
}


/* SIGILL handler — slow path.
 * 
 * Invoked when a patched UD2 (was: syscall) executes. Translates
 * the macOS BSD syscall number to Linux, translates arguments if
 * needed, executes the Linux syscall, and resumes the app.
 * 
 * For exit (BSD 1): prints stats before exiting.
 */

/* Crash handler for SIGSEGV/SIGBUS/SIGFPE — prints the faulting address
 * and register state so we can debug crashes in loaded macOS binaries.
 * Uses ONLY signal-safe functions (write, snprintf — NOT fprintf). */
void crash_handler(int sig, siginfo_t *info, void *uctx) {
    static char buf[1024];
    int n;

    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    uint64_t rip = (uint64_t)regs[REG_RIP];

    /* Build entire crash report in one buffer to minimize write calls
     * and avoid crashes between writes. Include Go state if available. */
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\nmacify: CRASH handler invoked\n"
        "sig=%d adr=%016lx\nrip=%016lx\nrsp=%016lx\nrbp=%016lx\n"
        "rax=%016lx\nrbx=%016lx\nrcx=%016lx\nrdx=%016lx\n"
        "rdi=%016lx\nrsi=%016lx\nr8 =%016lx\nr9 =%016lx\n"
        "r10=%016lx\nr11=%016lx\nr12=%016lx\nr13=%016lx\nr14=%016lx\nr15=%016lx\n",
        sig, (unsigned long)info->si_addr,
        (unsigned long)regs[REG_RIP], (unsigned long)regs[REG_RSP],
        (unsigned long)regs[REG_RBP],
        (unsigned long)regs[REG_RAX], (unsigned long)regs[REG_RBX],
        (unsigned long)regs[REG_RCX], (unsigned long)regs[REG_RDX],
        (unsigned long)regs[REG_RDI], (unsigned long)regs[REG_RSI],
        (unsigned long)regs[REG_R8],  (unsigned long)regs[REG_R9],
        (unsigned long)regs[REG_R10], (unsigned long)regs[REG_R11],
        (unsigned long)regs[REG_R12], (unsigned long)regs[REG_R13],
        (unsigned long)regs[REG_R14], (unsigned long)regs[REG_R15]);

    /* Go runtime state */
    pos += snprintf(buf + pos, sizeof(buf) - pos, "g_tls_g_addr=%lu\n", (unsigned long)g_tls_g_addr);
    if (g_tls_g_addr) {
        uint64_t g = 0;
        if (g_tls_g_addr > 0x10000 && g_tls_g_addr < 0x7fffffffffffUL)
            g = *(volatile uint64_t *)g_tls_g_addr;
        pos += snprintf(buf + pos, sizeof(buf) - pos, "Go tls_g=0x%lx\n", (unsigned long)g);
        if (g > 0x10000 && g < 0x7fffffffffffUL) {
            uint64_t m = *(volatile uint64_t *)(g + 0x30);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "g.m=0x%lx\n", (unsigned long)m);
            if (m > 0x10000 && m < 0x7fffffffffffUL) {
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                    "m.g0=0x%lx m.gsignal=0x%lx m.curg=0x%lx\n",
                    (unsigned long)*(volatile uint64_t *)m,
                    (unsigned long)*(volatile uint64_t *)(m + 0x48),
                    (unsigned long)*(volatile uint64_t *)(m + 0xb8));
            }
        }
    }

    write(2, buf, pos);

    /* Print first 16 stack entries to help debug rip=0 (NULL function pointer)
     * and other crashes. The return address is at [rsp]. */
    {
        char sb[160];
        int sn;
        uint64_t sp = (uint64_t)regs[REG_RSP];
        extern uint64_t g_tls_g_addr;
        /* Find rclone base for decoding return addresses */
        uint64_t rclone_base = 0;
        for (int i = 0; i < g_nsegments; i++) {
            if (g_segments[i].is_pagezero) continue;
            if (strcmp(g_segments[i].name, "__TEXT") == 0) {
                rclone_base = g_segments[i].vmaddr;
                break;
            }
        }
        sn = snprintf(sb, sizeof(sb), "\nstack (rclone_base=0x%lx):\n", (unsigned long)rclone_base);
        write(2, sb, sn);
        for (int i = 0; i < 32; i++) {
            uint64_t addr = sp + (uint64_t)i * 8;
            uint64_t val = 0;
            if (addr > 0x10000 && addr < 0x7fffffffffffUL) {
                val = *(volatile uint64_t *)addr;
            }
            char tag[32] = "";
            if (rclone_base && val >= rclone_base && val < rclone_base + 0x5000000) {
                snprintf(tag, sizeof(tag), " rclone+0x%lx", (unsigned long)(val - rclone_base));
            }
            sn = snprintf(sb, sizeof(sb), "  sp+%02d: 0x%016lx%s\n", i, (unsigned long)val, tag);
            write(2, sb, sn);
        }
    }

    print_stats();
    _exit(128 + sig);
}

/* Buffers for sigprocmask syscall translation (macOS 4-byte ↔ Linux 8-byte sigset_t).
 * File-scope so they can be accessed both pre- and post-syscall. */
static unsigned char linux_set_sigprocmask[8];
static unsigned char linux_oset_sigprocmask[8];

/* Buffers for sigaltstack syscall translation (macOS/Linux stack_t field order differs). */
#include <signal.h>
static stack_t linux_ss_sigaltstack;
static stack_t linux_oss_sigaltstack;

void sigill_handler(int sig, siginfo_t *info, void *uctx) {
    (void)sig; (void)info;
    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    uint64_t macos_nr = (uint64_t)regs[REG_RAX];
    uint32_t bsd_nr   = macos_nr & 0xFFFFFF;

    /* Debug: count SIGILL handler invocations */
    g_slow_path_calls++;
    if (getenv("MACIFY_TRACE_SIGILL") || (g_verbose && g_slow_path_calls <= 5)) {
        fprintf(stderr, "macify: SIGILL #%lu: bsd_nr=%u (rax=0x%llx)\n",
                g_slow_path_calls, bsd_nr, (unsigned long long)macos_nr);
    }

    /* Fast bounds check. Most syscalls are < 600. */
    if (__builtin_expect(bsd_nr >= BSD_SYSCALL_MAX, 0)) {
        fprintf(stderr,
                "\nmacify: unhandled macOS syscall 0x%llx (BSD #%u, out of range)\n",
                (unsigned long long)macos_nr, bsd_nr);
        _exit(127);
    }

    int16_t linux_nr = bsd_to_linux[bsd_nr];
    if (__builtin_expect(linux_nr <= 0, 0)) {
        /* linux_nr == 0 means "unimplemented" (unused table slot). */
        fprintf(stderr,
                "\nmacify: unhandled macOS syscall 0x%llx (BSD #%u = %s)\n",
                (unsigned long long)macos_nr, bsd_nr, bsd_syscall_name(bsd_nr));
        _exit(127);
    }

    uint8_t flags = bsd_arg_flags[bsd_nr];

    /* For exit (BSD 1): print stats, then exit_group. */
    if (__builtin_expect(bsd_nr == 1, 0)) {
        if (g_verbose) {
            fprintf(stderr, "macify: syscall exit(code=%lld)\n",
                    (long long)regs[REG_RDI]);
        }
        print_stats();
        raw_syscall(SYS_exit_group, regs[REG_RDI], 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }

    /* Extract args. */
    long a1 = regs[REG_RDI];
    long a2 = regs[REG_RSI];
    /* For sigprocmask: save original macOS oset pointer for post-syscall copy */
    void *sigprocmask_save_macos_oset = NULL;
    /* For sigaltstack: save original macOS oss pointer for post-syscall copy */
    void *sigaltstack_save_macos_oss = NULL;
    long a3 = regs[REG_RDX];
    long a4 = regs[REG_R10];
    long a5 = regs[REG_R8];
    long a6 = regs[REG_R9];

    /* Per-syscall argument translation. */
    if (flags & ARG_OPEN_FLAGS) {
        int old_a2 = (int)a2;
        a2 = (long)translate_open_flags(old_a2);
        if (g_verbose) {
            fprintf(stderr, "macify:   open flags macos=%#x -> linux=%#lx\n",
                    (unsigned)old_a2, a2);
        }
    }
    if (flags & ARG_MMAP_FLAGS) {
        int old_a4 = (int)a4;
        a4 = (long)translate_mmap_flags(old_a4);
        if (g_verbose) {
            fprintf(stderr, "macify:   mmap flags macos=%#x -> linux=%#lx\n",
                    (unsigned)old_a4, a4);
        }
    }
    if (flags & ARG_KILL_SIGNAL) {
        int old_a2 = (int)a2;
        a2 = (long)translate_kill_signal(old_a2);
        if (g_verbose) {
            fprintf(stderr, "macify:   kill signal macos=%d -> linux=%ld\n",
                    old_a2, a2);
        }
    }
    if (flags & ARG_FCNTL_CMD) {
        int old_a2 = (int)a2;
        int new_a2 = translate_fcntl_cmd(old_a2);
        if (new_a2 < 0) {
            /* macOS-specific cmd with no Linux equivalent. Return EINVAL. */
            if (g_verbose) {
                fprintf(stderr, "macify:   fcntl cmd macos=%d -> UNSUPPORTED\n",
                        old_a2);
            }
            regs[REG_RAX] = (greg_t)(-EINVAL);
            regs[REG_RIP] += 2;
            return;
        }
        a2 = (long)new_a2;
        if (g_verbose) {
            fprintf(stderr, "macify:   fcntl cmd macos=%d -> linux=%ld\n",
                    old_a2, a2);
        }
    }
    if (flags & ARG_MADVISE) {
        int old_a3 = (int)a3;
        a3 = (long)translate_madvise(old_a3);
        if (g_verbose) {
            fprintf(stderr, "macify:   madvise advice macos=%d -> linux=%ld\n",
                    old_a3, a3);
        }
    }
    if (flags & ARG_SIGACTION) {
        /* macOS sigaction(int signum, const struct sigaction *act,
         *                  struct sigaction *oldact)
         * a1 = signum, a2 = act (macOS struct ptr), a3 = oldact (macOS struct ptr)
         * Translate signal number from macOS to Linux (they differ!).
         */
        if (a1 == 4 /*SIGILL*/ || a1 == 11 /*SIGSEGV*/ || a1 == 10 /*SIGBUS*/) {
            /* NEVER let the macOS binary replace our SIGILL/SIGSEGV/SIGBUS
             * handlers. SIGILL is critical for syscall translation.
             * SIGSEGV/SIGBUS are our crash handlers. */
            if (g_verbose) {
                fprintf(stderr, "macify:   sigaction(%ld) - skipped, keeping our handler\n", a1);
            }
            regs[REG_RAX] = 0;  /* return success */
            regs[REG_RIP] += 2;  /* skip UD2 */
            return;
        }
        if (a2) {
            static struct {
                void *handler;
                unsigned long flags;
                void *restorer;
                unsigned char mask[128];
            } linux_sa;
            uint8_t *macos_sa = (uint8_t *)a2;
            memset(&linux_sa, 0, sizeof(linux_sa));
            unsigned int macos_flags = *(unsigned int *)(macos_sa + 12);
            void *go_handler = *(void **)macos_sa;

            /* For Go binaries: install the signal deferral wrapper instead
             * of Go's handler directly. This prevents signals from being
             * delivered before m.gsignal is allocated. */
            if (g_tls_g_addr) {
                /* Look up the wrapper and handler array from the shim */
                static void *(*p_wrapper)(void);
                static void **p_handlers;
                static int looked_up = 0;
                if (!looked_up) {
                    p_wrapper = dlsym(RTLD_DEFAULT, "macify_go_signal_wrapper");
                    p_handlers = dlsym(RTLD_DEFAULT, "macify_saved_go_handlers");
                    looked_up = 1;
                }
                if (p_wrapper && p_handlers) {
                    int linux_sig_for_handler = translate_kill_signal((int)a1);
                    if (linux_sig_for_handler > 0 && linux_sig_for_handler < 32) {
                        p_handlers[linux_sig_for_handler] = go_handler;
                    }
                    linux_sa.handler = p_wrapper;
                    linux_sa.flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
                } else {
                    /* Fallback: install Go's handler directly */
                    linux_sa.handler = go_handler;
                    linux_sa.flags = macos_flags | SA_ONSTACK;
                }
            } else {
                linux_sa.handler = go_handler;
                linux_sa.flags = macos_flags | SA_ONSTACK;
            }
            /* Translate the 4-byte macOS sigset mask to 128-byte Linux sigset,
             * translating signal numbers (macOS SIGURG=16 → Linux SIGURG=23, etc.) */
            uint32_t macos_mask = *(uint32_t *)(macos_sa + 8);
            sigset_t linux_mask;
            sigemptyset(&linux_mask);
            for (int ms = 1; ms <= 31; ms++) {
                if (macos_mask & (1u << (ms - 1))) {
                    int ls = translate_kill_signal(ms);
                    if (ls > 0) sigaddset(&linux_mask, ls);
                }
            }
            memcpy(&linux_sa.mask, &linux_mask, sizeof(linux_mask));
            a2 = (long)&linux_sa;
            int macos_signum = (int)a1;
            int linux_signum = translate_kill_signal(macos_signum);
            if (g_verbose) {
                fprintf(stderr, "macify:   sigaction signum macos=%d -> linux=%d handler=%p flags=0x%x -> 0x%lx\n",
                        macos_signum, linux_signum, linux_sa.handler, macos_flags, linux_sa.flags);
            }
            a1 = linux_signum;
        }
        if (a3) {
            static unsigned char linux_old_sa[152];
            a3 = (long)linux_old_sa;
        }
    }
    if (flags & ARG_SIGPROCMASK) {
        sigprocmask_save_macos_oset = (void *)a3;
        if (a2) {
            /* Translate 4-byte macOS sigset to 8-byte Linux sigset,
             * translating signal numbers (macOS SIGURG=16 → Linux SIGURG=23).
             * Just copying the bitmask would block the WRONG signals! */
            uint32_t macos_mask = *(uint32_t *)a2;
            uint64_t linux_mask = 0;
            for (int ms = 1; ms <= 31; ms++) {
                if (macos_mask & (1u << (ms - 1))) {
                    int ls = translate_kill_signal(ms);
                    if (ls > 0 && ls < 64) {
                        linux_mask |= (1ULL << (ls - 1));
                    }
                }
            }
            *(uint64_t *)linux_set_sigprocmask = linux_mask;
            a2 = (long)linux_set_sigprocmask;
        }
        if (a3) {
            a3 = (long)linux_oset_sigprocmask;
        }
        a4 = 8;  /* sigsetsize = sizeof(kernel_sigset_t) = 8 */
        if (g_verbose) {
            fprintf(stderr, "macify:   sigprocmask how=%ld set=%p oset=%p sigsetsize=8\n",
                    a1, (void *)a2, (void *)a3);
        }
    }
    if (flags & ARG_SIGALTSTACK) {
        sigaltstack_save_macos_oss = (void *)a2;
        if (a1) {
            uint8_t *macos_ss = (uint8_t *)a1;
            memset(&linux_ss_sigaltstack, 0, sizeof(linux_ss_sigaltstack));
            linux_ss_sigaltstack.ss_sp = *(void **)macos_ss;
            linux_ss_sigaltstack.ss_flags = *(int *)(macos_ss + 16);
            linux_ss_sigaltstack.ss_size = *(size_t *)(macos_ss + 8);

            /* If Go tries to DISABLE the signal stack (SS_DISABLE),
             * replace it with our own stack instead. Go disables the
             * signal stack when it's done with signal setup, but we
             * need it to stay active for crash handling. */
            if (linux_ss_sigaltstack.ss_flags & 0x1 /* SS_DISABLE */) {
                static char fallback_sigstack[256 * 1024] __attribute__((aligned(4096)));
                linux_ss_sigaltstack.ss_sp = fallback_sigstack;
                linux_ss_sigaltstack.ss_size = sizeof(fallback_sigstack);
                linux_ss_sigaltstack.ss_flags = 0;
            }
            a1 = (long)&linux_ss_sigaltstack;
        }
        if (a2) {
            a2 = (long)&linux_oss_sigaltstack;
        }
    }
    /* wait4 options WCONTINUED bit differs (macOS 0x4 vs Linux 0x8) but is
     * rarely used; left untranslated. */

    if (g_verbose) {
        fprintf(stderr, "macify: syscall %-16s macos=0x%-10llx -> linux=%-3d  "
                        "args=%#llx,%#llx,%#llx,%#llx,%#llx,%#llx\n",
                bsd_syscall_name(bsd_nr),
                (unsigned long long)macos_nr, (int)linux_nr,
                (unsigned long long)a1, (unsigned long long)a2,
                (unsigned long long)a3, (unsigned long long)a4,
                (unsigned long long)a5, (unsigned long long)a6);
    }

    long result = raw_syscall((long)linux_nr, a1, a2, a3, a4, a5, a6);

    /* Linux raw syscalls return -errno on failure (e.g., -9 for EBADF).
     * macOS raw syscalls return -1 on failure and set errno via __errno().
     * Real macOS apps check for -1, not -errno.
     *
     * We convert -errno → -1 and set errno via our shim's __errno() function.
     * The shim's __errno() returns __errno_location(), so errno is properly set. */
    /* Track whether the syscall errored (before converting -errno → -1).
     * Go's asmSyscall6 checks CF: CF=1 means error, CF=0 means success. */
    bool syscall_error = (result < 0 && result > -4096);

    if (__builtin_expect(syscall_error, 0)) {
        /* result is -errno. Set errno and convert to -1 (macOS convention). */
        int err = (int)(-result);
        errno = err;  /* Sets glibc's errno via __errno_location() */
        if (g_verbose) {
            fprintf(stderr, "macify:   syscall failed: linux returned %ld (-errno=%d), "
                            "converting to -1 (macOS convention)\n", result, err);
        }
        result = -1;
    }

    /* Post-syscall: for sigprocmask, translate 8-byte Linux sigset → 4-byte macOS sigset.
     * Must translate signal numbers back (Linux SIGURG=23 → macOS SIGURG=16). */
    if (flags & ARG_SIGPROCMASK) {
        if (sigprocmask_save_macos_oset && result == 0) {
            uint64_t linux_mask = *(uint64_t *)linux_oset_sigprocmask;
            uint32_t macos_mask = 0;
            for (int ls = 1; ls <= 31; ls++) {
                if (linux_mask & (1ULL << (ls - 1))) {
                    /* Find macOS signal that maps to this Linux signal */
                    for (int ms = 1; ms <= 31; ms++) {
                        if (translate_kill_signal(ms) == ls) {
                            macos_mask |= (1u << (ms - 1));
                            break;
                        }
                    }
                }
            }
            *(uint32_t *)sigprocmask_save_macos_oset = macos_mask;
        }
    }
    /* Post-syscall: for sigaltstack, convert Linux stack_t → macOS stack_t */
    if (flags & ARG_SIGALTSTACK) {
        if (sigaltstack_save_macos_oss && result == 0) {
            uint8_t *macos_oss = (uint8_t *)sigaltstack_save_macos_oss;
            *(void **)macos_oss = linux_oss_sigaltstack.ss_sp;           /* offset 0 */
            *(size_t *)(macos_oss + 8) = linux_oss_sigaltstack.ss_size;  /* macOS: size at 8 */
            *(int *)(macos_oss + 16) = linux_oss_sigaltstack.ss_flags;   /* macOS: flags at 16 */
        }
    }

    regs[REG_RAX] = (greg_t)result;

    /* Set carry flag to match macOS syscall convention.
     * macOS: CF=1 on error (errno set), CF=0 on success.
     * Linux: returns -errno on error, non-negative on success.
     * Go's asmSyscall6 checks CF via 'jae' (jump if CF=0 = success).
     * We must set EFLAGS.CF accordingly or Go misinterprets results. */
    if (syscall_error) {
        regs[REG_EFL] |= 0x0001;  /* set CF */
    } else {
        regs[REG_EFL] &= ~0x0001UL;  /* clear CF */
    }

    regs[REG_RIP] += 2;  /* skip past the 2-byte UD2 (0F 0B) */
}



#define BACKWARD_SCAN_BYTES 32

/* Helper: scan a byte range for syscall instructions and patch them.
 * base = segment base address (slid)
 * seg_start = offset within base where the range starts
 * seg_len = length of the range
 * Returns number of sites patched (fast + slow), or -1 on error. */
int patch_syscalls_in_range(loaded_segment *seg, uint8_t *base,
                                    size_t range_start, size_t range_len,
                                    int *fast_count, int *slow_count) {
    size_t range_end = range_start + range_len;
    if (range_end > seg->vmsize) range_end = seg->vmsize;

    for (size_t i = range_start; i + 1 < range_end; i++) {
        if (base[i] != 0x0F || base[i+1] != 0x05) continue;  /* not syscall */

        /* CRITICAL: Check that this 0F 05 is NOT inside another instruction.
         * The byte pattern 0F 05 can appear as:
         *   - Part of a JMP/CALL rel32 displacement (e.g., e9 0f 05 00 00)
         *   - Part of a LEA rip+disp32 displacement (e.g., 48 8d 35 0f 05 00 00)
         *   - Part of a MOV imm32 (e.g., b8 0f 05 00 00)
         *   - Part of a CMP imm32 (e.g., 81 f9 0f 05 00 00)
         *   - Part of conditional jump (e.g., 0f 84 0f 05 00 00)
         *
         * Strategy: only patch 0F 05 if we can find a macOS syscall pattern
         * within 32 bytes BEFORE it. Two patterns:
         *   1. mov eax, 0x2000XXXX (B8 XX XX 00 20) — static syscall number
         *   2. add rax, 0x2000000 (48 05 00 00 00 02) — Go's dynamic pattern:
         *      Go loads syscall number from stack/memory, adds 0x2000000 */
        {
            bool found_pattern = false;
            size_t scan_start = (i >= BACKWARD_SCAN_BYTES) ? (i - BACKWARD_SCAN_BYTES) : 0;
            for (size_t j = (i >= 5) ? (i - 5) : 0; j >= scan_start && j < i; j--) {
                /* Pattern 1: mov eax, 0x2000XXXX */
                if (base[j] == 0xB8 && j+4 < i &&
                    base[j+3] == 0x00 && base[j+4] == 0x20) {
                    if (j > 0 && base[j-1] >= 0x40 && base[j-1] <= 0x4F) continue;
                    found_pattern = true;
                    break;
                }
                /* Pattern 2: add rax, 0x2000000 (Go's dynamic syscall pattern)
                 * 48 05 00 00 00 02 = REX.W ADD RAX, imm32(0x02000000) */
                if (j >= 5 && base[j] == 0x48 && base[j+1] == 0x05 &&
                    base[j+2] == 0x00 && base[j+3] == 0x00 &&
                    base[j+4] == 0x00 && base[j+5] == 0x02) {
                    found_pattern = true;
                    break;
                }
                if (j == 0) break;
            }
            if (!found_pattern) continue;  /* Not a macOS syscall */
        }

        /* Found a syscall at offset i. Look backward for mov eax, 0x2000XXXX. */
        size_t mov_off = (size_t)-1;
        size_t mov_scan_start = (i >= BACKWARD_SCAN_BYTES) ? (i - BACKWARD_SCAN_BYTES) : 0;
        size_t scan_end   = (i >= 5) ? (i - 5) : 0;

        for (size_t j = scan_end + 1; j-- > mov_scan_start; ) {
            if (base[j] != 0xB8) continue;
            if (base[j+3] != 0x00 || base[j+4] != 0x20) continue;
            /* Skip if preceded by ANY REX prefix (0x40-0x4F). */
            if (j > 0 && base[j-1] >= 0x40 && base[j-1] <= 0x4F) continue;
            mov_off = j;
            break;
        }

        if (mov_off != (size_t)-1) {
            uint16_t bsd_nr = base[mov_off+1] | (base[mov_off+2] << 8);
            if (bsd_nr >= BSD_SYSCALL_MAX) {
                base[i+1] = 0x0B;  /* UD2 */
                (*slow_count)++;
                continue;
            }
            int16_t linux_nr = bsd_to_linux[bsd_nr];
            uint8_t flags = bsd_arg_flags[bsd_nr];
            bool needs_translation = (flags & ~ARG_FORCE_SLOW) != 0;
            bool force_slow = (flags & ARG_FORCE_SLOW) != 0;

            if (!g_no_fast_path && linux_nr > 0 && !needs_translation && !force_slow) {
                /* FAST PATH: rewrite the immediate. */
                base[mov_off+1] = (uint8_t)(linux_nr & 0xFF);
                base[mov_off+2] = (uint8_t)((linux_nr >> 8) & 0xFF);
                base[mov_off+3] = 0;
                base[mov_off+4] = 0;
                (*fast_count)++;
            } else {
                /* SLOW PATH: patch syscall to UD2. */
                base[i+1] = 0x0B;
                (*slow_count)++;
            }
        } else {
            /* No mov found: dynamically computed syscall #. SLOW PATH. */
            base[i+1] = 0x0B;
            if (g_verbose) {
                fprintf(stderr, "macify: patched dynamic syscall at offset 0x%lx (addr=%p, bytes now: %02x %02x)\n",
                        (unsigned long)i, (void *)(base + i), base[i], base[i+1]);
            }
            (*slow_count)++;
        }
    }
    return 0;
}

/* Forward declaration */
void patch_go_systemstack(loaded_segment *seg, uint8_t *base);

int patch_syscalls_in_segment(loaded_segment *seg) {
    if (!(seg->prot & PROT_EXEC)) return 0;
    if (seg->is_pagezero) return 0;

    if (mprotect((void *)(uintptr_t)seg->vmaddr, seg->vmsize,
                 PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        perror("mprotect RWX");
        return -1;
    }

    uint8_t *base = (uint8_t *)(uintptr_t)seg->vmaddr;
    int fast_count = 0, slow_count = 0;

    /* If we have section info, only patch code sections (more precise —
     * avoids false positives in data sections like __cstring, __const).
     * If no sections, patch the whole segment (backward compat). */
    bool has_code_sections = false;
    for (int i = 0; i < g_nsections; i++) {
        if (strncmp(g_sections[i].segname, seg->name, 16) == 0 &&
            section_is_code(&g_sections[i])) {
            has_code_sections = true;
            size_t sec_start = (size_t)(g_sections[i].addr - seg->vmaddr);
            size_t sec_len = (size_t)g_sections[i].size;
            patch_syscalls_in_range(seg, base, sec_start, sec_len,
                                    &fast_count, &slow_count);
            if (g_verbose) {
                fprintf(stderr, "macify: patched section %s.%s "
                                "(range %#lx+%lu, fast=%d slow=%d so far)\n",
                        g_sections[i].segname, g_sections[i].sectname,
                        (unsigned long)sec_start, (unsigned long)sec_len,
                        fast_count, slow_count);
            }
        }
    }

    if (!has_code_sections) {
        /* No code sections — scan the whole segment (legacy behavior) */
        patch_syscalls_in_range(seg, base, 0, seg->vmsize,
                                &fast_count, &slow_count);
    }

    /* Patch Go's systemstack to handle NULL m.curg.
     * This is safe for non-Go binaries — the pattern won't match. */
    patch_go_systemstack(seg, base);

    /* Downgrade to target protection. */
    if (mprotect((void *)(uintptr_t)seg->vmaddr, seg->vmsize,
                 seg->target_prot) < 0) {
        perror("mprotect final");
        return -1;
    }
    seg->prot = seg->target_prot;

    g_fast_path_sites += fast_count;
    g_slow_path_sites += slow_count;

    if (g_verbose) {
        fprintf(stderr, "macify: patched %d syscall site(s) in %s "
                        "(fast=%d, slow=%d%s)\n",
                fast_count + slow_count, seg->name, fast_count, slow_count,
                has_code_sections ? ", sections-only" : "");
    }
    return fast_count + slow_count;
}

/* Patch Go's systemstack function to handle NULL m.curg.
 * After running a function on g0's stack, systemstack tries to switch
 * back to m.curg's stack:
 *   mov gs:0x30, rax       ; set tls_g = m.curg (OK even if NULL)
 *   mov rsp, [rax+0x38]    ; CRASH if rax=m.curg=0!
 *   mov rbp, [rax+0x60]    ; also crashes
 *
 * We keep "mov gs:0x30, rax" intact (so tls_g gets set correctly),
 * and patch the following 8 bytes (mov rsp + mov rbp) to:
 *   test rax, rax          ; if m.curg is NULL...
 *   je +0x13 (to pop rbp; ret) ; ...skip stack switch and return
 *   nop * 3                ; padding
 * When m.curg is non-NULL, the nops run and the original mov rsp/rbp
 * are skipped — BUT that breaks the stack switch!
 *
 * Actually, we need a different approach. We patch ONLY the 4-byte
 * "mov rsp, [rax+0x38]" to a conditional that checks rax:
 * But 4 bytes isn't enough for test+je.
 *
 * Final approach: patch the 13-byte sequence starting at mov gs:0x30:
 *   Original (13 bytes): 65 48 89 04 25 30 00 00 00 48 8b 60 38
 *   Patched: 48 85 c0 74 07 65 48 89 04 25 30 00 00
 *   = test rax, rax; je +7; mov gs:0x30, rax
 *   If rax=0: skip mov gs:0x30 and the stack switch (je to mov rbp)
 *   If rax!=0: set tls_g, then fall through to mov rsp (unchanged at +13)
 * But mov rsp is at offset 13 and we only patched 13 bytes...
 * The mov rsp [rax+0x38] still runs if rax!=0. But if rax=0, we je past it.
 *
 * je +7: from offset 5 (end of je) to offset 12 = 7 bytes.
 * Offset 12 is the last byte of the original mov gs (0x38 of mov rsp).
 * That's wrong.
 *
 * Let me just use a simple approach:
 * Patch 13 bytes: test rax,rax; je +8; mov gs:0x30,rax; (mov rsp stays)
 * If rax=0: je to offset 13 = start of mov rsp, but rax is 0 so it crashes.
 * That doesn't help.
 *
 * OK, simplest correct approach: patch 14 bytes (mov gs + mov rsp):
 *   65 48 89 04 25 30 00 00 00 48 8b 60 38 XX
 * To:
 *   48 85 c0 74 08 65 48 89 04 25 30 00 00 90
 *   = test rax, rax; je +8; mov gs:0x30, rax; nop
 * If rax=0: je to offset 13 = nop, then falls through to mov rbp (which
 * also crashes). Still bad.
 *
 * ACTUAL simplest: just patch the 4-byte 'mov rsp, [rax+0x38]' to a
 * 4-byte 'ret' if rax is 0. Use CDQ+js trick? No.
 *
 * Just use: 48 85 c0 90 (test rax, rax; nop) replacing mov rsp.
 * Then the NEXT instruction (mov rbp, [rax+0x60]) will crash if rax=0.
 * But at least we can catch it.
 *
 * Actually the BEST approach: don't patch systemstack at all.
 * Instead, set m.curg = m.g0 BEFORE calling the Go entry point,
 * but do it AFTER rt0_go has set up g0 and m0. We can do this
 * in setup_gs_base after finding tls_g (which is near m0 in BSS). */
void patch_go_systemstack(loaded_segment *seg, uint8_t *base) {
    /* Patch systemstack's "switch back to m.curg" code.
     *
     * When m.curg is NULL (before any goroutine is scheduled), systemstack
     * crashes at mov rsp, [rax+0x38] where rax=m.curg=0.
     *
     * We patch 14 bytes (mov gs + mov rsp + REX) with:
     *   test rax, rax (3) — check m.curg
     *   je to trampoline (2) — if NULL: jump to trampoline (not pop rbp!)
     *   jmp trampoline2 (5) — if non-NULL: jump to trampoline2
     *   nop*4 (4)
     *
     * Trampoline (NULL m.curg path, in int3 padding):
     *   mov rax, [rbx] (3) — rax = m.g0 (rbx = g.m, m.g0 is at m+0)
     *   mov gs:0x30, rax (9) — set tls_g = m.g0 (keep valid g!)
     *   jmp to pop rbp;ret (5)
     * Total: 17 bytes
     *
     * Trampoline2 (non-NULL m.curg path, in int3 padding after trampoline):
     *   mov gs:0x30, rax (9) — set tls_g = m.curg
     *   mov rsp, [rax+0x38] (4) — switch stacks
     *   mov rbp, [rax+0x68] (4) — restore rbp
     *   jmp back to clearing (5)
     * Total: 22 bytes
     *
     * When m.curg=0: tls_g is set to m.g0 (NOT zeroed!), then return.
     * When m.curg!=0: original behavior (set tls_g, switch stacks, clear).
     */
    uint8_t pattern[] = {
        0x65, 0x48, 0x89, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0x48, 0x8b, 0x60, 0x38,
        0x48
    };

    for (size_t i = 0; i + sizeof(pattern) + 20 < seg->vmsize; i++) {
        if (memcmp(base + i, pattern, sizeof(pattern)) != 0) continue;
        if (base[i+14] != 0x8b || base[i+15] != 0x68) continue;

        /* Find int3 padding for TWO trampolines (need 17+22=39 bytes) */
        size_t trampoline_off = 0;
        for (size_t j = i + 20; j + 39 < seg->vmsize; j++) {
            if (base[j] == 0xCC && base[j+1] == 0xCC && base[j+2] == 0xCC) {
                size_t pad = 0;
                while (j + pad < seg->vmsize && base[j + pad] == 0xCC) pad++;
                if (pad >= 39) { trampoline_off = j; break; }
            }
        }
        if (trampoline_off == 0) continue;

        /* Find pop rbp; ret (5d c3) */
        size_t pop_ret_off = 0;
        for (size_t j = i + 17; j < i + 50; j++) {
            if (base[j] == 0x5d && base[j+1] == 0xc3) { pop_ret_off = j; break; }
        }
        if (pop_ret_off == 0) continue;

        /* Trampoline1 (NULL m.curg path) at trampoline_off:
         *   mov rax, [rbx] (3 bytes: 48 8b 03) — rax = m.g0 (rbx = g.m, m+0 = m.g0)
         *   mov gs:0x30, rax (9 bytes: 65 48 89 04 25 30 00 00 00)
         *   jmp to pop rbp;ret (5 bytes: E9 XX XX XX XX)
         * Total: 17 bytes */
        size_t t1_off = trampoline_off;
        int32_t t1_jmp_to_pop = (int32_t)(pop_ret_off - (t1_off + 17 + 5));

        uint8_t t1[22]; /* 17 bytes + padding */
        t1[0] = 0x48; t1[1] = 0x8b; t1[2] = 0x03;  /* mov rax, [rbx] (m.g0) */
        memcpy(&t1[3], pattern, 9);                  /* mov gs:0x30, rax */
        t1[12] = 0xE9;                               /* jmp to pop rbp;ret */
        memcpy(&t1[13], &t1_jmp_to_pop, 4);
        memset(&t1[17], 0x90, 5);                    /* nop padding */
        memcpy(base + t1_off, t1, 22);

        /* Trampoline2 (non-NULL m.curg path) at trampoline_off + 22:
         *   mov gs:0x30, rax (9 bytes)
         *   mov rsp, [rax+0x38] (4 bytes)
         *   mov rbp, [rax+0x68] (4 bytes)
         *   jmp back to clearing at i+17 (5 bytes)
         * Total: 22 bytes */
        size_t t2_off = trampoline_off + 22;
        int32_t t2_jmp_back = (int32_t)((i + 17) - (t2_off + 22));

        uint8_t t2[22];
        memcpy(&t2[0], pattern, 9);      /* mov gs:0x30, rax */
        memcpy(&t2[9], &pattern[9], 4);  /* mov rsp, [rax+0x38] */
        t2[13] = 0x48; t2[14] = 0x8b; t2[15] = 0x68; t2[16] = base[i+16];
        t2[17] = 0xE9;
        memcpy(&t2[18], &t2_jmp_back, 4);
        memcpy(base + t2_off, t2, 22);

        /* Patch 14 bytes: test + je(near) + jmp + nop
         * Use near je (0F 84) because trampoline may be far away.
         * test rax, rax (3) + je near (6) + jmp (5) = 14 bytes. Perfect! */
        int32_t je_offset = (int32_t)(t1_off - (i + 3 + 6));  /* from end of je */
        int32_t jmp_offset = (int32_t)(t2_off - (i + 14));    /* from end of jmp */

        uint8_t patch[14];
        patch[0] = 0x48; patch[1] = 0x85; patch[2] = 0xC0;  /* test rax, rax */
        patch[3] = 0x0F; patch[4] = 0x84;                    /* je near (4-byte offset) */
        memcpy(&patch[5], &je_offset, 4);
        patch[9] = 0xE9;                                      /* jmp to trampoline2 */
        memcpy(&patch[10], &jmp_offset, 4);
        memcpy(base + i, patch, sizeof(patch));

        if (g_verbose) {
            fprintf(stderr, "macify: patched systemstack at 0x%lx -> t1=0x%lx t2=0x%lx\n",
                    (unsigned long)(seg->vmaddr + i),
                    (unsigned long)(seg->vmaddr + t1_off),
                    (unsigned long)(seg->vmaddr + t2_off));
        }
        return;
    }
}

/* Print all loaded libraries (for crash debugging). */
static int dl_iterate_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    const char *name = info->dlpi_name;
    if (!name || !*name) name = "(main executable)";
    fprintf(stderr, "    base=0x%lx name=%s\n",
            (unsigned long)info->dlpi_addr, name);
    return 0;
}

int print_loaded_libs(void) {
    fprintf(stderr, "  Loaded libraries:\n");
    dl_iterate_phdr(dl_iterate_cb, NULL);
    return 0;
}
