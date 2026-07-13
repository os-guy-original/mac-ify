/* sigmask.c — signal number translation, pthread_sigmask, sigprocmask, sigaltstack */
#include "signal_internal.h"
#include <signal.h>

/* ── pthread_sigmask / sigprocmask ────────────────────────────
 *
 * macOS sigset_t = 4 bytes (uint32_t), Linux sigset_t = 128 bytes.
 * Go's runtime calls pthread_sigmask with a 4-byte sigset, but glibc's
 * pthread_sigmask reads 128 bytes, getting garbage in bytes 4-127.
 * This causes EINVAL for signals > 31, making Go abort during init.
 *
 * We override to translate between 4-byte (macOS) and 128-byte (Linux)
 * sigsets. The caller check ensures we only translate for macOS callers;
 * glibc's internal calls pass through unmodified. */

/* macOS → Linux signal number translation.
 * Signals 1-6 are the same. From 7 onward they diverge.
 * Returns 0 if the macOS signal has no Linux equivalent. */
/* Export this for use in other shim files (e.g., pthread_kill in shim_pthread.c) */
int macos_sig_to_linux_signal(int macos_sig) {
    return macos_sig_to_linux(macos_sig);
}

int macos_sig_to_linux(int macos_sig) {
    static const int xlate[32] = {
        [0]  = 0,  [1] = 1,  [2] = 2,  [3] = 3,  [4] = 4,  [5] = 5,  [6] = 6,
        [7]  = 0,   /* SIGEMT — no Linux equiv */
        [8]  = 8,   /* SIGFPE */
        [9]  = 9,   /* SIGKILL */
        [10] = 7,   /* macOS SIGBUS → Linux SIGBUS (7) */
        [11] = 11,  /* SIGSEGV */
        [12] = 31,  /* macOS SIGSYS → Linux SIGSYS (31) */
        [13] = 13,  /* SIGPIPE */
        [14] = 14,  /* SIGALRM */
        [15] = 15,  /* SIGTERM */
        [16] = 23,  /* macOS SIGURG → Linux SIGURG (23) */
        [17] = 19,  /* macOS SIGSTOP → Linux SIGSTOP (19) */
        [18] = 20,  /* macOS SIGTSTP → Linux SIGTSTP (20) */
        [19] = 18,  /* macOS SIGCONT → Linux SIGCONT (18) */
        [20] = 17,  /* macOS SIGCHLD → Linux SIGCHLD (17) */
        [21] = 21,  /* SIGTTIN */
        [22] = 22,  /* SIGTTOU */
        [23] = 29,  /* macOS SIGIO → Linux SIGIO (29) */
        [24] = 24,  /* SIGXCPU */
        [25] = 25,  /* SIGXFSZ */
        [26] = 26,  /* SIGVTALRM */
        [27] = 27,  /* SIGPROF */
        [28] = 28,  /* SIGWINCH */
        [29] = 0,   /* macOS SIGINFO — no Linux equiv */
        [30] = 10,  /* macOS SIGUSR1 → Linux SIGUSR1 (10) */
        [31] = 12,  /* macOS SIGUSR2 → Linux SIGUSR2 (12) */
    };
    if (macos_sig < 0 || macos_sig >= 32) return macos_sig;
    return xlate[macos_sig];
}

/* Linux → macOS signal number translation (reverse). */
int linux_sig_to_macos(int linux_sig) {
    static int xlate[32];
    static int initialized = 0;
    if (!initialized) {
        memset(xlate, 0, sizeof(xlate));
        for (int m = 0; m < 32; m++) {
            int l = macos_sig_to_linux(m);
            if (l > 0 && l < 32) xlate[l] = m;
        }
        initialized = 1;
    }
    if (linux_sig < 0 || linux_sig >= 32) return linux_sig;
    return xlate[linux_sig] ? xlate[linux_sig] : linux_sig;
}

/* Expand a 4-byte macOS sigset to a 128-byte Linux sigset.
 * CRITICAL: translates signal numbers (macOS SIGURG=16 → Linux SIGURG=23, etc.)
 * NOT just bit positions! */
void macos_to_linux_sigset(const void *macos_set, sigset_t *linux_set) {
    uint32_t macos_mask = *(const uint32_t *)macos_set;
    static int (*real_sigemptyset)(sigset_t *) = NULL;
    if (!real_sigemptyset) real_sigemptyset = dlsym(RTLD_NEXT, "sigemptyset");
    real_sigemptyset(linux_set);
    for (int macos_sig = 1; macos_sig <= 31; macos_sig++) {
        if (macos_mask & (1u << (macos_sig - 1))) {
            int linux_sig = macos_sig_to_linux(macos_sig);
            if (linux_sig > 0) {
                static int (*real_sigaddset)(sigset_t *, int) = NULL;
                if (!real_sigaddset) real_sigaddset = dlsym(RTLD_NEXT, "sigaddset");
                real_sigaddset(linux_set, linux_sig);
            }
        }
    }
}

/* Compress a 128-byte Linux sigset to a 4-byte macOS sigset.
 * Translates signal numbers back (Linux SIGURG=23 → macOS SIGURG=16, etc.) */
void linux_to_macos_sigset(const sigset_t *linux_set, void *macos_set) {
    uint32_t macos_mask = 0;
    static int (*real_sigismember)(const sigset_t *, int) = NULL;
    if (!real_sigismember) real_sigismember = dlsym(RTLD_NEXT, "sigismember");
    for (int linux_sig = 1; linux_sig <= 31; linux_sig++) {
        if (real_sigismember(linux_set, linux_sig)) {
            int macos_sig = linux_sig_to_macos(linux_sig);
            if (macos_sig > 0 && macos_sig <= 31) {
                macos_mask |= (1u << (macos_sig - 1));
            }
        }
    }
    *(uint32_t *)macos_set = macos_mask;
}

int macify_pthread_sigmask(int how, const void *set, void *oldset) __asm__("pthread_sigmask");
int macify_pthread_sigmask(int how, const void *set, void *oldset) {
    /* If the caller is NOT macOS text, pass through to glibc.
     * glibc internally calls pthread_sigmask with 128-byte sigsets. */
    if (!macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Non-macOS caller: use glibc's real pthread_sigmask.
         * Using raw syscall(14) bypasses glibc's internal locks, causing
         * futex deadlocks. Use real_dlsym to avoid infinite recursion. */
        static int (*real_pthread_sigmask)(int, const sigset_t *, sigset_t *) = NULL;
        if (!real_pthread_sigmask) {
            real_pthread_sigmask = real_dlsym(RTLD_NEXT, "pthread_sigmask");
        }
        if (real_pthread_sigmask) {
            return real_pthread_sigmask(how, (const sigset_t *)set, (sigset_t *)oldset);
        }
        return syscall(14, how, set, oldset, 8);
    }

    /* Translate macOS sigset how values to Linux:
     *   macOS: SIG_BLOCK=1, SIG_UNBLOCK=2, SIG_SETMASK=3
     *   Linux: SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2
     * Go passes macOS values, which glibc rejects as invalid. */
    int linux_how;
    switch (how) {
        case 1: linux_how = SIG_BLOCK; break;    /* macOS SIG_BLOCK -> Linux SIG_BLOCK */
        case 2: linux_how = SIG_UNBLOCK; break;  /* macOS SIG_UNBLOCK -> Linux SIG_UNBLOCK */
        case 3: linux_how = SIG_SETMASK; break;  /* macOS SIG_SETMASK -> Linux SIG_SETMASK */
        default: linux_how = how; break;  /* already Linux value or unknown */
    }

    /* macOS caller: translate 4-byte sigset to 128-byte */
    sigset_t linux_set, linux_oldset;
    sigset_t *p_linux_set = NULL;
    sigset_t *p_linux_oldset = NULL;

    if (set) {
        macos_to_linux_sigset(set, &linux_set);
        /* CRITICAL: Never let macOS code block SIGSEGV(11), SIGBUS(7),
         * SIGABRT(6), or SIGILL(4). Our crash handlers MUST remain
         * deliverable, otherwise a crash kills the process with exit
         * code 139 before the handler can recover/flush output. */
        if (linux_how == SIG_BLOCK || linux_how == SIG_SETMASK) {
            sigdelset(&linux_set, 11);  /* SIGSEGV */
            sigdelset(&linux_set, 7);   /* SIGBUS */
            sigdelset(&linux_set, 6);   /* SIGABRT */
            sigdelset(&linux_set, 4);   /* SIGILL */
        }
        p_linux_set = &linux_set;
        if (getenv("MACIFY_SHIM_DEBUG")) {
            uint32_t mm = *(const uint32_t *)set;
            fprintf(stderr, "macify: pthread_sigmask(how=%d, macos_mask=0x%x -> linux)\n",
                    how, mm);
        }
    }
    if (oldset) {
        p_linux_oldset = &linux_oldset;
    }

    /* Use raw rt_sigprocmask syscall (can't use dlsym — causes infinite recursion) */
    int result = syscall(14, linux_how, p_linux_set, p_linux_oldset, 8);

    if (oldset && result == 0) {
        linux_to_macos_sigset(&linux_oldset, oldset);
    }
    return result;
}

int macify_sigprocmask(int how, const void *set, void *oldset) __asm__("sigprocmask");
int macify_sigprocmask(int how, const void *set, void *oldset) {
    /* If the caller is NOT macOS text, pass through to glibc. */
    if (!macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Use glibc's real sigprocmask to avoid futex deadlocks */
        static int (*real_sigprocmask)(int, const sigset_t *, sigset_t *) = NULL;
        if (!real_sigprocmask) {
            real_sigprocmask = real_dlsym(RTLD_NEXT, "sigprocmask");
        }
        if (real_sigprocmask) {
            return real_sigprocmask(how, (const sigset_t *)set, (sigset_t *)oldset);
        }
        return syscall(14, how, set, oldset, 8);
    }

    /* Translate macOS how values to Linux */
    int linux_how;
    switch (how) {
        case 1: linux_how = SIG_BLOCK; break;
        case 2: linux_how = SIG_UNBLOCK; break;
        case 3: linux_how = SIG_SETMASK; break;
        default: linux_how = how; break;
    }

    sigset_t linux_set, linux_oldset;
    sigset_t *p_linux_set = NULL;
    sigset_t *p_linux_oldset = NULL;

    if (set) {
        macos_to_linux_sigset(set, &linux_set);
        /* CRITICAL: Never let macOS code block SIGSEGV(11), SIGBUS(7),
         * SIGABRT(6), or SIGILL(4). Our crash handlers MUST remain
         * deliverable. */
        if (linux_how == SIG_BLOCK || linux_how == SIG_SETMASK) {
            sigdelset(&linux_set, 11);  /* SIGSEGV */
            sigdelset(&linux_set, 7);   /* SIGBUS */
            sigdelset(&linux_set, 6);   /* SIGABRT */
            sigdelset(&linux_set, 4);   /* SIGILL */
        }
        p_linux_set = &linux_set;
    }
    if (oldset) {
        p_linux_oldset = &linux_oldset;
    }

    /* Use raw rt_sigprocmask syscall (can't use dlsym — causes infinite recursion) */
    int result = syscall(14, linux_how, p_linux_set, p_linux_oldset, 8);

    if (getenv("MACIFY_TRACE_SIGNAL")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: sigprocmask(how=%d, set=%p, oldset=%p) = %d from %p\n",
            how, set, oldset, result, __builtin_return_address(0));
        (void)write(2, b, n);
    }

    if (oldset && result == 0) {
        linux_to_macos_sigset(&linux_oldset, oldset);
    }
    return result;
}

/* sigaltstack: macOS and Linux have different stack_t layouts!
 * macOS: ss_sp(8), ss_size(8), ss_flags(4)+pad(4) = 24 bytes
 * Linux: ss_sp(8), ss_flags(4)+pad(4), ss_size(8) = 24 bytes
 * Field order differs — ss_size and ss_flags are swapped.
 *
 * We translate the struct layout and call the real sigaltstack.
 * This is critical for Go binaries which need their own signal stack
 * for gsignal goroutine. Without it, Go crashes in systemstack. */
int macify_sigaltstack(const void *ss, void *oss) __asm__("sigaltstack");
int macify_sigaltstack(const void *ss, void *oss) {
    if (getenv("MACIFY_TRACE_SIGNAL")) {
        char b[256];
        if (ss) {
            const uint8_t *m = (const uint8_t *)ss;
            void *sp = *(void *const *)m;
            size_t sz = *(const size_t *)(m + 8);
            int fl = *(const int *)(m + 16);
            snprintf(b, sizeof(b), "macify: sigaltstack(ss={sp=%p size=%zu flags=0x%x}, oss=%p) from %p\n",
                    sp, sz, fl, oss, __builtin_return_address(0));
        } else {
            snprintf(b, sizeof(b), "macify: sigaltstack(ss=NULL, oss=%p) from %p\n", oss, __builtin_return_address(0));
        }
        (void)write(2, b, strlen(b));
    }
    stack_t linux_ss, linux_oss;
    stack_t *p_ss = NULL, *p_oss = NULL;

    if (ss) {
        const uint8_t *macos_ss = (const uint8_t *)ss;
        memset(&linux_ss, 0, sizeof(linux_ss));
        linux_ss.ss_sp = *(void *const *)macos_ss;
        linux_ss.ss_size = *(const size_t *)(macos_ss + 8);
        linux_ss.ss_flags = *(const int *)(macos_ss + 16);

        /* NEVER allow disabling the signal stack — our crash handler
         * requires SA_ONSTACK to work. */
        if (linux_ss.ss_flags & 0x1 /* SS_DISABLE */) {
            return 0;  /* pretend success but don't disable */
        }

        if (linux_ss.ss_flags & 0x1 /* SS_DISABLE */) {
        }
        p_ss = &linux_ss;
    }
    if (oss) {
        p_oss = &linux_oss;
    }

    /* Call the real sigaltstack via raw syscall (bypass glibc, which might
     * not be findable via dlsym due to symbol interposition). */
    int result = syscall(131, p_ss, p_oss);

    if (oss && result == 0) {
        /* Convert Linux-format stack_t back to macOS format */
        uint8_t *macos_oss = (uint8_t *)oss;
        *(void **)macos_oss = linux_oss.ss_sp;            /* offset 0 */
        *(size_t *)(macos_oss + 8) = linux_oss.ss_size;   /* macOS: size at 8 */
        *(int *)(macos_oss + 16) = linux_oss.ss_flags;    /* macOS: flags at 16 */
    }
    return result;
}

