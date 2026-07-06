/* flag_translation.c — translate macOS flags to Linux for open/mmap/kill/fcntl/madvise */
#include "syscall_internal.h"

/* Syscall argument translation
 * 
 * Most syscalls take the same args on macOS and Linux (file
 * descriptors, pointers, sizes). A few take flag bitmasks whose
 * numeric values differ between the two systems.
 */

int translate_open_flags(int macos_flags) {
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
int translate_mmap_flags(int macos_flags) {
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
int translate_kill_signal(int macos_sig) {
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
int translate_fcntl_cmd(int macos_cmd) {
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
int translate_madvise(int macos_advice) {
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


