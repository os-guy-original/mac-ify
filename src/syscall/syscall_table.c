/* syscall_table.c — BSD→Linux syscall number table and argument flags */
#include "syscall_internal.h"

/* Syscall translation table — flat array indexed by BSD syscall #.
 * macOS x86_64 syscall numbers: 0x2000000 | BSD_NR, where BSD_NR is 0..~500.
 * Each entry is the Linux syscall number, or 0 if unimplemented.
 *
 * BSD numbers verified against xnu bsd/kern/syscalls.master
 * (apple-oss-distributions/xnu). Do not "fix" entries against memory —
 * several historical entries here were shifted or invented and caused
 * silent misrouting (e.g. openat(463) -> rt_sigprocmask).
 *
 * Deliberately unmapped despite existing on both systems (struct layouts
 * differ and the slow path cannot translate them):
 *   stat(188)/fstat(189)/lstat(190), statfs(157)/fstatfs(158),
 *   getdirentries(196)/getdirentries64(344), stat64 family (338-343),
 *   fstatat(469/470), waitid(173) — shim handles these at symbol level.
 * Deliberately unmapped (arg count/semantics differ):
 *   xattr family (234-241: macOS has extra position/options args),
 *   posix_spawn(244), psynch_*(297-312), __pthread_*(328/329),
 *   __semwait_signal(334), kqueue(362), bsdthread_*(360/361/366/478).
 */

const int16_t bsd_to_linux[BSD_SYSCALL_MAX] = {
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
    [41]  = SYS_dup,        /* dup            */
    [42]  = SYS_pipe,       /* pipe           */
    [43]  = SYS_getegid,    /* getegid        */
    [46]  = SYS_rt_sigaction, /* sigaction    */
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
    [82]  = SYS_setpgid,    /* setpgid        */
    [83]  = SYS_setitimer,  /* setitimer      */
    [86]  = SYS_getitimer,  /* getitimer      */
    [90]  = SYS_dup2,       /* dup2           */
    [92]  = SYS_fcntl,      /* fcntl          */
    [93]  = SYS_select,     /* select         */
    [95]  = SYS_fsync,      /* fsync          */
    [96]  = SYS_setpriority,/* setpriority    */
    [97]  = SYS_socket,     /* socket         (type identical) */
    [98]  = SYS_connect,    /* connect        */
    [100] = SYS_getpriority,/* getpriority    */
    [116] = SYS_gettimeofday, /* gettimeofday */
    [117] = SYS_getrusage,  /* getrusage      (struct layout same) */
    [118] = SYS_getsockopt, /* getsockopt     */
    [120] = SYS_readv,      /* readv          */
    [121] = SYS_writev,     /* writev         */
    [122] = SYS_settimeofday, /* settimeofday */
    [123] = SYS_fchown,     /* fchown         */
    [124] = SYS_fchmod,     /* fchmod         */
    [126] = SYS_setreuid,   /* setreuid       */
    [127] = SYS_setregid,   /* setregid       */
    [128] = SYS_rename,     /* rename         */
    [131] = SYS_flock,      /* flock          (op identical) */
    [133] = SYS_sendto,     /* sendto         */
    [134] = SYS_shutdown,   /* shutdown       (how identical) */
    [135] = SYS_socketpair, /* socketpair     */
    [136] = SYS_mkdir,      /* mkdir          */
    [137] = SYS_rmdir,      /* rmdir          */
    [138] = SYS_utimes,     /* utimes         */
    [147] = SYS_setsid,     /* setsid         */
    [151] = SYS_getpgid,    /* getpgid        */
    [153] = SYS_pread64,    /* pread          */
    [154] = SYS_pwrite64,   /* pwrite         */
    [187] = SYS_fdatasync,  /* fdatasync      */
    [197] = SYS_mmap,       /* mmap           (flags translated) */
    [199] = SYS_lseek,      /* lseek          */
    [200] = SYS_truncate,   /* truncate       */
    [201] = SYS_ftruncate,  /* ftruncate      */
    [203] = SYS_mlock,      /* mlock          */
    [204] = SYS_munlock,    /* munlock        */
    [230] = SYS_poll,       /* poll           (struct pollfd identical) */
    [396] = SYS_read,       /* read_nocancel          */
    [397] = SYS_write,      /* write_nocancel         */
    [398] = SYS_open,       /* open_nocancel (ARG_OPEN_FLAGS) */
    [399] = SYS_close,      /* close_nocancel         */
    [400] = SYS_wait4,      /* wait4_nocancel         */
    [401] = SYS_recvmsg,    /* recvmsg_nocancel       */
    [402] = SYS_sendmsg,    /* sendmsg_nocancel       */
    [403] = SYS_recvfrom,   /* recvfrom_nocancel      */
    [404] = SYS_accept,     /* accept_nocancel        */
    [405] = SYS_msync,      /* msync_nocancel         */
    [406] = SYS_fcntl,      /* fcntl_nocancel         */
    [407] = SYS_select,     /* select_nocancel        */
    [408] = SYS_fsync,      /* fsync_nocancel         */
    [409] = SYS_connect,    /* connect_nocancel       */
    [411] = SYS_readv,      /* readv_nocancel         */
    [412] = SYS_writev,     /* writev_nocancel        */
    [413] = SYS_sendto,     /* sendto_nocancel        */
    [414] = SYS_pread64,    /* pread_nocancel         */
    [415] = SYS_pwrite64,   /* pwrite_nocancel        */
    [417] = SYS_poll,       /* poll_nocancel          */
    [463] = SYS_openat,     /* openat         (ARG_OPEN_FLAGS; raw fd-relative
                             * paths only — no prefix translation here) */
    [464] = SYS_openat,     /* openat_nocancel        */
    [465] = SYS_renameat,   /* renameat               */
    [466] = SYS_faccessat,  /* faccessat              */
    [467] = SYS_fchmodat,   /* fchmodat               */
    [468] = SYS_fchownat,   /* fchownat               */
    [472] = SYS_unlinkat,   /* unlinkat               */
    [473] = SYS_readlinkat, /* readlinkat             */
    [500] = SYS_getrandom,  /* getentropy -> getrandom(flags=0) */
    /* All other entries are 0 (unimplemented): slow path reports the
     * syscall name and exits 127 (or returns ENOSYS under
     * MACIFY_LENIENT_SYSCALLS=1). */
};

/* Argument translation flags. */

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

const uint16_t bsd_arg_flags[BSD_SYSCALL_MAX] = {
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
    [406] = ARG_FCNTL_CMD,                    /* fcntl_nocancel */
    [463] = ARG_OPEN_FLAGS,                   /* openat */
    [464] = ARG_OPEN_FLAGS,                   /* openat_nocancel */
    /* wait4 (7) options WCONTINUED bit differs (macOS 0x4 vs Linux 0x8) but is
     * rarely used. */
};
