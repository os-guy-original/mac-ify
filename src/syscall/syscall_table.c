/* syscall_table.c — BSD→Linux syscall number table and argument flags */
#include "syscall_internal.h"

#define BSD_SYSCALL_MAX 600


/* Syscall translation table — flat array indexed by BSD syscall #.
 * macOS x86_64 syscall numbers: 0x2000000 | BSD_NR, where BSD_NR is 0..~500
 * for the syscalls we care about. Each entry is the Linux syscall number,
 * or -1 if unimplemented. Argument translation flags live in a parallel
 * array.
 */

#define BSD_SYSCALL_MAX 600

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

const uint8_t bsd_arg_flags[BSD_SYSCALL_MAX] = {
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

