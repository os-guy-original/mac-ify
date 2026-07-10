/* sigaction.c — sigaction() and signal() overrides with macOS→Linux translation */
#include "signal_internal.h"
#include <signal.h>

int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (getenv("MACIFY_TRACE_SIGNAL")) {
        char b[128]; int n = snprintf(b, sizeof(b), "macify: sigaction(sig=%d, act=%p, oldact=%p) from %p\n",
                signum, act, oldact, __builtin_return_address(0));
        (void)write(2, b, n);
    }

    /* If the caller is NOT macOS text (e.g., macify's own code or glibc
     * internals), pass through directly to glibc's sigaction without any
     * translation. The act/oldact are already in Linux format.
     * CRITICAL: If we translate a Linux-format struct sigaction as if it
     * were a macOS-format struct, the flags and mask fields are read from
     * the wrong offsets, causing signal handlers to be installed with
     * wrong flags (no SA_ONSTACK, no SA_SIGINFO, no SA_RESTORER). */
    if (!macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Non-macOS caller: pass through to kernel via raw rt_sigaction syscall.
         * We can't use glibc's sigaction() because our dlsym override might
         * return our shim's sigaction instead of glibc's. The raw syscall
         * goes directly to the kernel.
         * CRITICAL: We must set SA_RESTORER and sa_restorer, because the
         * kernel requires it on modern Linux. Glibc's sigaction wrapper
         * normally does this, but we're bypassing it. */
        if (act) {
            struct sigaction modified_act = *act;
            if (!(modified_act.sa_flags & 0x04000000) && macify_sa_restorer) {
                modified_act.sa_flags |= 0x04000000;  /* SA_RESTORER */
                modified_act.sa_restorer = macify_sa_restorer;
            }
            return syscall(13, signum, &modified_act, oldact, 8);
        }
        return syscall(13, signum, NULL, oldact, 8);
    }

    /* macOS caller: translate signal number and struct layout.
     * CRITICAL: Don't allow macOS binaries to override SIGSEGV/SIGABRT
     * handlers — our crash recovery handler must remain installed to
     * catch FILE* layout incompatibility crashes. */
    {
        /* Block macOS code from replacing our crash handlers */
        if (signum == 11 /* SIGSEGV */ || signum == 6 /* SIGABRT */) {
            if (act) {
                /* macOS binary is trying to install its own SIGSEGV/SIGABRT
                 * handler. Silently ignore — our handler must stay. */
                return 0;
            }
        }
        static const int sig_xlate[32] = {
            [0]  = 0, [1] = 1, [2] = 2, [3] = 3, [4] = 4, [5] = 5, [6] = 6,
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
        if (signum >= 0 && signum < 32 && sig_xlate[signum]) {
            signum = sig_xlate[signum];
        }
    }

    if (!real_sigaction) {
        real_sigaction = real_dlsym(RTLD_NEXT, "sigaction");
    }
    struct sigaction linux_act;
    struct sigaction linux_oldact;
    struct sigaction *p_linux_act = NULL;
    struct sigaction *p_linux_oldact = NULL;

    if (act) {
        struct macos_sigaction *macos_act = (struct macos_sigaction *)act;
        memset(&linux_act, 0, sizeof(linux_act));
        linux_act.sa_handler = macos_act->handler;

        /* Translate macOS sa_flags to Linux sa_flags.
         * macOS and Linux use COMPLETELY DIFFERENT bit values for SA_* flags!
         * macOS: SA_ONSTACK=0x0001, SA_RESTART=0x0002, SA_SIGINFO=0x0040
         * Linux: SA_ONSTACK=0x08000000, SA_RESTART=0x10000000, SA_SIGINFO=0x00000004
         * Without this translation, SA_ONSTACK and SA_SIGINFO are NOT set on Linux,
         * causing signal handlers to run on the wrong stack without siginfo. */
        uint32_t macos_flags = macos_act->flags;
        uint32_t linux_flags = 0;
        if (macos_flags & 0x0001) linux_flags |= 0x08000000;  /* SA_ONSTACK */
        if (macos_flags & 0x0002) linux_flags |= 0x10000000;  /* SA_RESTART */
        if (macos_flags & 0x0004) linux_flags |= 0x80000000;  /* SA_RESETHAND */
        if (macos_flags & 0x0008) linux_flags |= 0x00000001;  /* SA_NOCLDSTOP */
        if (macos_flags & 0x0010) linux_flags |= 0x40000000;  /* SA_NODEFER */
        if (macos_flags & 0x0020) linux_flags |= 0x00000002;  /* SA_NOCLDWAIT */
        if (macos_flags & 0x0040) linux_flags |= 0x00000004;  /* SA_SIGINFO */
        if (macos_flags & 0x0080) linux_flags |= 0x04000000;  /* SA_RESTORER (not used on macOS, but just in case) */
        linux_act.sa_flags = linux_flags;

        if (getenv("MACIFY_TRACE_SIGNAL")) {
            char b[128]; int n = snprintf(b, sizeof(b),
                "macify: sigaction handler=%p flags=0x%x->0x%x for sig=%d\n",
                macos_act->handler, macos_flags, linux_flags, signum);
            (void)write(2, b, n);
        }
        sigemptyset(&linux_act.sa_mask);
        /* Translate the 4-byte macOS sigset mask to 128-byte Linux sigset,
         * translating signal numbers (macOS SIGURG=16 → Linux SIGURG=23, etc.) */
        if (macos_act->mask) {
            uint32_t macos_mask = macos_act->mask;
            for (int ms = 1; ms <= 31; ms++) {
                if (macos_mask & (1u << (ms - 1))) {
                    int ls = macos_sig_to_linux(ms);
                    if (ls > 0) sigaddset(&linux_act.sa_mask, ls);
                }
            }
        }
        /* For SIGSEGV/SIGBUS: install OUR crash handler with SA_ONSTACK
         * so it runs on the alternate signal stack (set up in the constructor).
         * Without SA_ONSTACK, a stack overflow prevents the handler from
         * running because there's no stack space to push the signal frame. */
        /* For SIGSEGV/SIGBUS: install OUR crash handler with SA_ONSTACK.
         * Note: at this point, signum is already translated to Linux numbers.
         * Linux SIGSEGV=11, SIGBUS=7, SIGILL=4. */
        if (signum == 11 /*SIGSEGV*/ || signum == 7 /*SIGBUS*/) {
            /* For macOS callers: install our crash handler.
             * For non-macOS callers (macify itself): pass through. */
            if (macify_caller_is_macos_text(__builtin_return_address(0))) {
                linux_act.sa_sigaction = macify_crash_handler;
                linux_act.sa_flags = SA_SIGINFO | SA_ONSTACK;
                /* Add SA_RESTORER — required on modern Linux kernels */
                if (macify_sa_restorer) {
                    linux_act.sa_flags |= 0x04000000;  /* SA_RESTORER */
                    linux_act.sa_restorer = macify_sa_restorer;
                }
            }
            p_linux_act = &linux_act;
        } else if (signum == SIGILL) {
            /* Only block SIGILL installation from macOS binary callers.
             * macify's own sigaction(SIGILL, sigill_handler, ...) must go
             * through, otherwise syscall translation (UD2 → SIGILL) breaks.
             *
             * For macOS binary callers: NEVER let them replace our SIGILL
             * handler. Our SIGILL handler is critical for syscall translation.
             * We silently ignore the sigaction call and keep our handler. */
            if (macify_caller_is_macos_text(__builtin_return_address(0))) {
                if (getenv("MACIFY_SHIM_DEBUG")) {
                    fprintf(stderr, "macify: sigaction(SIGILL) from macOS text - keeping our handler (syscall translation)\n");
                }
                p_linux_act = NULL;  /* don't install */
            }
            /* For non-macOS callers (macify itself): pass through normally */
        } else {
            /* For all other signals (including SIGURG for async preemption):
             * Install our wrapper that restores GS base before calling Go's
             * handler. This is CRITICAL for async preemption — Go's
             * sigtrampgo reads gs:0x30 to find the current g, and if GS base
             * was clobbered by signal delivery, it reads garbage. */
            extern uint64_t g_tls_g_addr;
            if (g_tls_g_addr) {
                /* Go binary: install signal wrapper that restores GS base */
                extern void macify_go_signal_wrapper(int, siginfo_t *, void *);
                extern void *macify_saved_go_handlers[];
                if (signum >= 0 && signum < 32) {
                    macify_saved_go_handlers[signum] = (void *)macos_act->handler;
                }
                linux_act.sa_sigaction = macify_go_signal_wrapper;
                linux_act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
            } else {
                /* Non-Go: just add SA_ONSTACK and pass through */
                linux_act.sa_flags |= SA_ONSTACK;
            }
            /* CRITICAL: Add SA_RESTORER and set sa_restorer. */
            if (macify_sa_restorer) {
                linux_act.sa_flags |= 0x04000000;  /* SA_RESTORER */
                linux_act.sa_restorer = macify_sa_restorer;
            }
            p_linux_act = &linux_act;
        }
    }
    if (oldact) {
        p_linux_oldact = &linux_oldact;
    }

    /* Use raw rt_sigaction syscall instead of real_sigaction, because
     * real_sigaction might be NULL (glibc loaded before shim, so
     * real_dlsym(RTLD_NEXT, "sigaction") returns NULL).
     * The linux_act already has SA_RESTORER and sa_restorer set. */
    int result = syscall(13, signum, p_linux_act, p_linux_oldact, 8);

    if (oldact && result == 0) {
        struct macos_sigaction *macos_old = (struct macos_sigaction *)oldact;
        macos_old->handler = linux_oldact.sa_handler;
        macos_old->flags = linux_oldact.sa_flags;
        uint32_t macos_mask = 0;
        memcpy(&macos_mask, &linux_oldact.sa_mask, sizeof(uint32_t));
        macos_old->mask = macos_mask;
    }
    return result;
}
/* signal() — glibc's signal() calls __sigaction internally, bypassing our
 * sigaction override. The Rust runtime calls signal(SIGSEGV, ...) which
 * would override our crash handler. We intercept signal() for SIGSEGV/
 * SIGBUS and install our own handler. */
sighandler_t macify_signal(int signum, sighandler_t handler) __asm__("signal");
sighandler_t macify_signal(int signum, sighandler_t handler) {
    if (signum == SIGSEGV || signum == SIGBUS || signum == SIGABRT) {
        /* Install our crash handler via raw rt_sigaction syscall */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = macify_crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
        if (macify_sa_restorer) {
            sa.sa_flags |= 0x04000000;  /* SA_RESTORER */
            sa.sa_restorer = macify_sa_restorer;
        }
        sigemptyset(&sa.sa_mask);
        syscall(13, signum, &sa, NULL, 8);
        return SIG_DFL;
    }
    if (signum == SIGILL) {
        /* Never let the macOS binary replace our SIGILL handler. */
        return SIG_DFL;
    }
    /* For other signals: convert signal() to raw rt_sigaction syscall
     * with SA_ONSTACK and SA_RESTORER. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_ONSTACK;
    if (macify_sa_restorer) {
        sa.sa_flags |= 0x04000000;  /* SA_RESTORER */
        sa.sa_restorer = macify_sa_restorer;
    }
    sigemptyset(&sa.sa_mask);
    syscall(13, signum, &sa, NULL, 8);
    return SIG_DFL;
}

