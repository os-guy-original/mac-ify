#include "shim.h"

/* atfork child handler: immediately exit forked children.
 * glibc's NSS forks helper processes via clone() (bypassing our fork
 * override). The child runs a copy of the macOS binary and deadlocks.
 * This handler runs in the child after fork and exits immediately,
 * allowing the parent's wait4 to return. */
static void atfork_child_handler(void) {
    _exit(0);
}

void atfork_child_exit(void) {
    pthread_atfork(NULL, NULL, atfork_child_handler);
}

/* Track the original PID to detect forked children. glibc's NSS calls
 * clone() directly (bypassing atfork handlers), so we detect children
 * by checking if getpid() != g_original_pid. In forked children, we
 * override read() to return 0 (EOF) to break the pipe deadlock. */
static pid_t g_original_pid = 0;

int is_forked_child(void) {
    if (g_original_pid == 0) g_original_pid = getpid();
    return getpid() != g_original_pid;
}

/* Constructor to initialize the stdio pointers */
__attribute__((constructor))
static void macify_init_stdio(void) {
    __stderrp = stderr;
    __stdinp = stdin;
    __stdoutp = stdout;

    /* Print shim load address for debugging */
    if (getenv("MACIFY_SHIM_DEBUG")) {
        Dl_info info;
        if (dladdr((void*)macify_init_stdio, &info)) {
            char b[128];
            int n = snprintf(b, sizeof(b), "macify: shim base = %p (macify_init_stdio at %p)\n",
                    info.dli_fbase, (void*)macify_init_stdio);
            (void)write(2, b, n);
        }
    }

    /* Allocate a dedicated signal stack (256KB) so our crash handler can
     * run even if the main stack overflows. Without this, a stack overflow
     * kills the process silently (signal handler can't push a frame). */
    static char sigstack[256 * 1024] __attribute__((aligned(4096)));
    stack_t ss;
    ss.ss_sp = sigstack;
    ss.ss_size = sizeof(sigstack);
    ss.ss_flags = 0;
    /* Use raw syscall to bypass our own sigaltstack override */
    syscall(131, &ss, NULL);  /* 131 = sigaltstack */

    /* Install our crash handler via raw rt_sigaction syscall (13).
     * Use SA_ONSTACK so the handler runs on the alternate signal stack.
     * SA_SIGINFO(4) | SA_NODEFER(0x40000000) | SA_ONSTACK(0x8000000) */
    struct k_sigaction {
        void (*handler)(int, siginfo_t *, void *);
        unsigned long flags;
        unsigned long mask[16];
    };
    struct k_sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.handler = macify_crash_handler;
    sa.flags = 0x08040004;  /* SA_SIGINFO | SA_NODEFER | SA_ONSTACK */
    long r;
    r = syscall(13, 11, &sa, NULL, 8);  /* SIGSEGV */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGSEGV failed: %ld\n",r); write(2,b,n); }
    r = syscall(13, 7,  &sa, NULL, 8);  /* SIGBUS */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGBUS failed: %ld\n",r); write(2,b,n); }
    r = syscall(13, 6,  &sa, NULL, 8);  /* SIGABRT */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGABRT failed: %ld\n",r); write(2,b,n); }
    r = syscall(13, 8,  &sa, NULL, 8);  /* SIGFPE */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGFPE failed: %ld\n",r); write(2,b,n); }

    /* Register pthread_atfork handler to immediately exit forked children.
     * glibc's NSS subsystem calls clone() internally (bypassing our fork
     * override) to create helper processes. The child runs a copy of the
     * macOS binary, which deadlocks (parent waits in wait4, child blocks
     * on pipe_read). By calling _exit(0) in the child handler, the child
     * exits immediately and the parent's wait4 returns successfully.
     * glibc's NSS then falls back to direct file-based lookups. */
    atfork_child_exit();
}
/* macOS struct sigaction has a completely different layout from Linux's.
 * macOS: sa_handler(8) + sa_mask(4, uint32) + sa_flags(4) = ~16 bytes
 * Linux: sa_handler(8) + sa_flags(8) + sa_mask(128) + sa_restorer(8) = ~144 bytes
 *
 * When glibc's sigaction reads a macOS-format struct, it reads 128 bytes
 * for sa_mask from a 4-byte field, corrupting the stack. This caused
 * ripgrep to crash with a NULL function pointer call after sigaction
 * overwrote stack variables.
 *
 * We override sigaction to translate the struct layout. Also override
 * sigprocmask/pthread_sigmask for the same sigset_t size mismatch. */
#include <signal.h>

/* macOS sigaction layout (x86_64):
 *   offset 0:  handler/sigaction function pointer (8 bytes)
 *   offset 8:  sa_mask (4 bytes, sigset_t = uint32_t)
 *   offset 12: sa_flags (4 bytes)
 * We access fields by offset to avoid macro conflicts with glibc's
 * struct sigaction field names. */
int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);

/* Saved Rust signal handlers — we chain to these after printing crash info. */
static void (*rust_segv_handler)(int) = NULL;
static void (*rust_bus_handler)(int) = NULL;

/* Our crash handler that prints info and exits. Must be async-signal-safe
 * (only use write(), not fprintf). */
void macify_crash_handler(int sig, siginfo_t *info, void *uctx) {
    /* Minimal crash handler — just write signal info and exit. */
    const char msg[] = "\nmacify: CRASH handler invoked\n";
    write(2, msg, sizeof(msg) - 1);

    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    char buf[128];

    /* Write the signal number and fault address */
    buf[0] = '\n';
    buf[1] = 's'; buf[2] = 'i'; buf[3] = 'g'; buf[4] = '=';
    buf[5] = '0' + (sig / 10);
    buf[6] = '0' + (sig % 10);
    buf[7] = ' ';
    buf[8] = 'a'; buf[9] = 'd'; buf[10] = 'r'; buf[11] = '=';
    uint64_t fault_addr = (uint64_t)info->si_addr;
    for (int i = 0; i < 16; i++) {
        int nibble = (fault_addr >> (60 - i*4)) & 0xf;
        buf[12+i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
    }
    buf[28] = '\n';
    write(2, buf, 29);

    /* Helper to print a register */
    #define PRINT_REG(name, val) do { \
        buf[0] = name[0]; buf[1] = name[1]; buf[2] = name[2]; buf[3] = '='; \
        for (int i = 0; i < 16; i++) { \
            int nibble = ((val) >> (60 - i*4)) & 0xf; \
            buf[4+i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10; \
        } \
        buf[20] = '\n'; \
        write(2, buf, 21); \
    } while(0)

    PRINT_REG("rip", (uint64_t)regs[REG_RIP]);
    PRINT_REG("rsp", (uint64_t)regs[REG_RSP]);
    PRINT_REG("rbp", (uint64_t)regs[REG_RBP]);
    PRINT_REG("rax", (uint64_t)regs[REG_RAX]);
    PRINT_REG("rbx", (uint64_t)regs[REG_RBX]);
    PRINT_REG("rcx", (uint64_t)regs[REG_RCX]);
    PRINT_REG("rdx", (uint64_t)regs[REG_RDX]);
    PRINT_REG("rdi", (uint64_t)regs[REG_RDI]);
    PRINT_REG("rsi", (uint64_t)regs[REG_RSI]);
    PRINT_REG("r8 ", (uint64_t)regs[REG_R8]);
    PRINT_REG("r9 ", (uint64_t)regs[REG_R9]);
    PRINT_REG("r10", (uint64_t)regs[REG_R10]);
    PRINT_REG("r11", (uint64_t)regs[REG_R11]);
    PRINT_REG("r12", (uint64_t)regs[REG_R12]);
    PRINT_REG("r13", (uint64_t)regs[REG_R13]);
    PRINT_REG("r14", (uint64_t)regs[REG_R14]);
    PRINT_REG("r15", (uint64_t)regs[REG_R15]);

    /* Print stack entries (skip for Go binaries — rsp may be corrupted) */
    extern uint64_t g_tls_g_addr;
    if (!g_tls_g_addr) {
        write(2, "stack:\n", 7);
        uint64_t *sp = (uint64_t *)regs[REG_RSP];
        for (int s = 0; s < 8; s++) {
            uint64_t val = sp[s];
            buf[0] = 's'; buf[1] = 'p'; buf[2] = '+'; buf[3] = '0' + s; buf[4] = ':';
            for (int i = 0; i < 16; i++) {
                int nibble = (val >> (60 - i*4)) & 0xf;
                buf[5+i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            buf[21] = '\n';
            write(2, buf, 22);
        }
    } else {
        /* Go binary: print runtime state instead of stack dump.
         * Go 1.26 m struct: m+0x00=g0, m+0x48=gsignal, m+0xb8=curg */
        uint64_t g = 0;
        if (g_tls_g_addr > 0x10000 && g_tls_g_addr < 0x7fffffffffffUL)
            g = *(volatile uint64_t *)g_tls_g_addr;
        /* Print g value */
        write(2, "Go g=", 5);
        for (int i = 0; i < 16; i++) {
            int nibble = (g >> (60 - i*4)) & 0xf;
            buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
        }
        buf[16] = '\n';
        write(2, buf, 17);

        if (g > 0x10000 && g < 0x7fffffffffffUL) {
            uint64_t m = *(volatile uint64_t *)(g + 0x30);
            uint64_t gsignal = 0, curg = 0, g0 = 0;
            if (m > 0x10000 && m < 0x7fffffffffffUL) {
                g0 = *(volatile uint64_t *)m;
                gsignal = *(volatile uint64_t *)(m + 0x48);
                curg = *(volatile uint64_t *)(m + 0xb8);
            }
            /* Print m.g0, m.gsignal, m.curg */
            write(2, "m.g0=", 5);
            for (int i = 0; i < 16; i++) {
                int nibble = (g0 >> (60 - i*4)) & 0xf;
                buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            buf[16] = ' '; buf[17] = '\n';
            write(2, buf, 18);

            write(2, "m.gsignal=", 10);
            for (int i = 0; i < 16; i++) {
                int nibble = (gsignal >> (60 - i*4)) & 0xf;
                buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            buf[16] = '\n';
            write(2, buf, 17);

            write(2, "m.curg=", 7);
            for (int i = 0; i < 16; i++) {
                int nibble = (curg >> (60 - i*4)) & 0xf;
                buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            buf[16] = '\n';
            write(2, buf, 17);
        }
    }

    _exit(128 + sig);
}

/* Forward declaration — defined later in this file. */
static int macos_sig_to_linux(int macos_sig);

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    /* Translate macOS signal number to Linux signal number — but ONLY
     * if the caller is macOS code. macify's own code uses Linux signal
     * numbers and should not be translated. */
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
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
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");
    }
    struct sigaction linux_act;
    struct sigaction linux_oldact;
    struct sigaction *p_linux_act = NULL;
    struct sigaction *p_linux_oldact = NULL;

    if (act) {
        struct macos_sigaction *macos_act = (struct macos_sigaction *)act;
        memset(&linux_act, 0, sizeof(linux_act));
        linux_act.sa_handler = macos_act->handler;
        linux_act.sa_flags = macos_act->flags;
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
            linux_act.sa_sigaction = macify_crash_handler;
            linux_act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
            p_linux_act = &linux_act;
        } else if (signum == SIGILL) {
            /* NEVER let the macOS binary replace our SIGILL handler.
             * Our SIGILL handler is critical for syscall translation
             * (the slow path uses UD2 instructions to trigger SIGILL).
             * If the macOS binary installs its own SIGILL handler,
             * syscall translation breaks and the binary crashes.
             * We silently ignore the sigaction call and keep our handler. */
            if (getenv("MACIFY_SHIM_DEBUG")) {
                fprintf(stderr, "macify: sigaction(SIGILL) - keeping our handler (syscall translation)\n");
            }
            p_linux_act = NULL;  /* don't install */
        } else {
            /* For all other signals: ensure SA_ONSTACK is set.
             * Go's runtime requires ALL signal handlers to use SA_ONSTACK.
             * For Go binaries, we install a wrapper that defers signal
             * delivery until gsignal is ready. */
            extern uint64_t g_tls_g_addr;
            if (g_tls_g_addr) {
                /* Go binary: install signal deferral wrapper */
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
            p_linux_act = &linux_act;
        }
    }
    if (oldact) {
        p_linux_oldact = &linux_oldact;
    }

    int result = real_sigaction(signum, p_linux_act, p_linux_oldact);

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
    if (signum == SIGSEGV || signum == SIGBUS) {
        /* Install our crash handler via real sigaction */
        if (!real_sigaction) {
            real_sigaction = dlsym(RTLD_NEXT, "sigaction");
        }
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = macify_crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        real_sigaction(signum, &sa, NULL);
        return SIG_DFL;
    }
    if (signum == SIGILL) {
        /* Never let the macOS binary replace our SIGILL handler. */
        return SIG_DFL;
    }
    /* For other signals: convert signal() to sigaction() with SA_ONSTACK.
     * Go requires all signal handlers to use SA_ONSTACK. */
    if (!real_sigaction) {
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    real_sigaction(signum, &sa, NULL);
    return SIG_DFL;
}

/* sigaddset/sigemptyset/sigfillset: macOS sigset_t = 4 bytes, Linux = 128.
 * glibc's versions write 128 bytes into a 4-byte buffer, corrupting the
 * stack. We override to work with the macOS 4-byte sigset_t. */
int sigaddset(sigset_t *set, int signum) {
    if (!set) return -1;
    uint32_t *mask = (uint32_t *)set;
    *mask |= (1u << (signum - 1));
    return 0;
}

int sigdelset(sigset_t *set, int signum) {
    if (!set) return -1;
    uint32_t *mask = (uint32_t *)set;
    *mask &= ~(1u << (signum - 1));
    return 0;
}

int sigemptyset(sigset_t *set) {
    if (!set) return -1;
    *(uint32_t *)set = 0;
    return 0;
}

int sigfillset(sigset_t *set) {
    if (!set) return -1;
    *(uint32_t *)set = 0xFFFFFFFF;
    return 0;
}

int sigismember(const sigset_t *set, int signum) {
    if (!set) return 0;
    uint32_t mask = *(const uint32_t *)set;
    return (mask & (1u << (signum - 1))) ? 1 : 0;
}

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
static int macos_sig_to_linux(int macos_sig) {
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
static int linux_sig_to_macos(int linux_sig) {
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
static void macos_to_linux_sigset(const void *macos_set, sigset_t *linux_set) {
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
static void linux_to_macos_sigset(const sigset_t *linux_set, void *macos_set) {
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
        static int (*real_pthread_sigmask)(int, const sigset_t *, sigset_t *) = NULL;
        if (!real_pthread_sigmask) real_pthread_sigmask = dlsym(RTLD_NEXT, "pthread_sigmask");
        return real_pthread_sigmask(how, (const sigset_t *)set, (sigset_t *)oldset);
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

    static int (*real_pthread_sigmask)(int, const sigset_t *, sigset_t *) = NULL;
    if (!real_pthread_sigmask) real_pthread_sigmask = dlsym(RTLD_NEXT, "pthread_sigmask");
    int result = real_pthread_sigmask(linux_how, p_linux_set, p_linux_oldset);

    if (oldset && result == 0) {
        linux_to_macos_sigset(&linux_oldset, oldset);
    }
    return result;
}

int macify_sigprocmask(int how, const void *set, void *oldset) __asm__("sigprocmask");
int macify_sigprocmask(int how, const void *set, void *oldset) {
    /* If the caller is NOT macOS text, pass through to glibc. */
    if (!macify_caller_is_macos_text(__builtin_return_address(0))) {
        static int (*real_sigprocmask)(int, const sigset_t *, sigset_t *) = NULL;
        if (!real_sigprocmask) real_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");
        return real_sigprocmask(how, (const sigset_t *)set, (sigset_t *)oldset);
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
        p_linux_set = &linux_set;
    }
    if (oldset) {
        p_linux_oldset = &linux_oldset;
    }

    static int (*real_sigprocmask)(int, const sigset_t *, sigset_t *) = NULL;
    if (!real_sigprocmask) real_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");
    int result = real_sigprocmask(linux_how, p_linux_set, p_linux_oldset);

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
    stack_t linux_ss, linux_oss;
    stack_t *p_ss = NULL, *p_oss = NULL;

    if (ss) {
        const uint8_t *macos_ss = (const uint8_t *)ss;
        memset(&linux_ss, 0, sizeof(linux_ss));
        linux_ss.ss_sp = *(void *const *)macos_ss;
        linux_ss.ss_size = *(const size_t *)(macos_ss + 8);
        linux_ss.ss_flags = *(const int *)(macos_ss + 16);

        /* If Go tries to DISABLE the signal stack (SS_DISABLE),
         * replace with our own to keep crash handling working. */
        if (linux_ss.ss_flags & 0x1 /* SS_DISABLE */) {
            static char fallback_ss[256 * 1024] __attribute__((aligned(4096)));
            linux_ss.ss_sp = fallback_ss;
            linux_ss.ss_size = sizeof(fallback_ss);
            linux_ss.ss_flags = 0;
        }
        p_ss = &linux_ss;
    }
    if (oss) {
        p_oss = &linux_oss;
    }

    /* Call the real sigaltstack (glibc's, via dlsym) */
    static int (*real_sigaltstack)(const stack_t *, stack_t *) = NULL;
    if (!real_sigaltstack) real_sigaltstack = dlsym(RTLD_NEXT, "sigaltstack");
    int result = real_sigaltstack(p_ss, p_oss);

    if (oss && result == 0) {
        /* Convert Linux-format stack_t back to macOS format */
        uint8_t *macos_oss = (uint8_t *)oss;
        *(void **)macos_oss = linux_oss.ss_sp;            /* offset 0 */
        *(size_t *)(macos_oss + 8) = linux_oss.ss_size;   /* macOS: size at 8 */
        *(int *)(macos_oss + 16) = linux_oss.ss_flags;    /* macOS: flags at 16 */
    }
    return result;
}

/* sigprocmask and pthread_sigmask: NOT overridden.
 *
 * Previously we tried to translate macOS 4-byte sigset_t to Linux 128-byte,
 * but this broke glibc's internal calls (glibc calls sigprocmask with 128-byte
 * sigsets, and our override corrupted them by treating them as 4-byte).
 *
 * The macOS binary's sigset_t is 4 bytes, but glibc's is 128 bytes. When the
 * macOS binary passes a 4-byte sigset to glibc's sigprocmask, glibc reads 128
 * bytes from the stack. The extra 124 bytes are garbage, but since macOS only
 * uses signals 1-31 (which fit in the first 4 bytes), and Linux rarely uses
 * signals 33+, the garbage in bytes 4-127 is unlikely to cause issues.
 *
 * The sigaddset/sigemptyset/sigfillset overrides still use 4-byte sigsets,
 * so the macOS binary's code works correctly. Only the actual sigprocmask
 * call passes the 4-byte sigset to glibc's 128-byte implementation. */

/* macify_get_shim_symbol — return our shim's override for a given symbol.
 * Used by dl.c's dlsym override to ensure Go (and other binaries) get our
 * translated sigaction/sigaltstack/signal instead of glibc's. */
void *macify_get_shim_symbol(const char *symbol) {
    if (strcmp(symbol, "sigaction") == 0) {
        /* Return the address of our sigaction override.
         * Use inline assembly to get the symbol address without
         * conflicting with system header declarations. */
        extern int sigaction(int, const struct sigaction *, struct sigaction *);
        return (void *)sigaction;
    }
    if (strcmp(symbol, "sigaltstack") == 0) {
        return (void *)macify_sigaltstack;
    }
    if (strcmp(symbol, "signal") == 0) {
        return (void *)macify_signal;
    }
    return NULL;
}

/* ── Go signal deferral wrapper ────────────────────────────────
 * Go's signal handler (sigtrampgo) crashes if a signal arrives before
 * m.gsignal is allocated. We wrap Go's handler and defer signal delivery
 * until Go is ready.
 *
 * "Go ready" is detected by checking if g_tls_g_addr is non-NULL AND
 * the value at *g_tls_g_addr is non-NULL (meaning Go has written &g0
 * to tls_g during rt0_go). After that point, Go's runtime has set up
 * gsignal and can handle signals safely. */

/* Saved Go signal handlers (indexed by Linux signal number). */
void *macify_saved_go_handlers[32] = {0};
static volatile int macify_go_signal_ready = 0;

/* Called by the wrapper to check if Go is ready for signals. */
static int go_is_ready(void) {
    if (macify_go_signal_ready) return 1;
    /* Check if Go has written to tls_g (meaning rt0_go has run)
     * AND m.gsignal is allocated (meaning signal handler can run safely). */
    extern uint64_t g_tls_g_addr;
    if (g_tls_g_addr) {
        uint64_t g = *(volatile uint64_t *)g_tls_g_addr;
        if (g != 0) {
            /* Check m.gsignal: g.m is at g+0x30, m.gsignal is at m+0xb8 */
            uint64_t m = *(volatile uint64_t *)(g + 0x30);
            if (m != 0) {
                uint64_t gsignal = *(volatile uint64_t *)(m + 0xb8);
                if (gsignal != 0) {
                    macify_go_signal_ready = 1;
                    return 1;
                }
            }
        }
    }
    return 0;
}

void macify_go_signal_wrapper(int sig, siginfo_t *info, void *uctx) {
    /* CRITICAL: Restore GS base before calling Go's handler.
     * On kernel 5.10, signal delivery can cause a context switch that
     * restores the stale shadow GS base. We must use BOTH wrgsbase
     * (sets CPU register) AND arch_prctl (syncs kernel shadow) to
     * ensure they're in sync. Without arch_prctl, the shadow is stale
     * and the next context switch clobbers GS base to 0. */
    extern uint64_t g_tls_g_addr;
    if (g_tls_g_addr) {
        uint64_t gs_base = g_tls_g_addr - 0x30;
        __asm__ volatile("wrgsbase %0" :: "r"(gs_base));
        syscall(158, 0x1001, gs_base);  /* ARCH_SET_GS — sync shadow */
    }

    if (go_is_ready()) {
        /* Go is ready — call the saved Go handler */
        if (sig >= 0 && sig < 32 && macify_saved_go_handlers[sig]) {
            void (*go_handler)(int, siginfo_t *, void *) =
                (void (*)(int, siginfo_t *, void *))macify_saved_go_handlers[sig];
            go_handler(sig, info, uctx);
            return;
        }
    }
    /* Go is NOT ready — defer the signal by re-blocking it.
     * The signal will be re-delivered when Go unblocks it via sigprocmask. */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    sigprocmask(SIG_BLOCK, &mask, NULL);
}
