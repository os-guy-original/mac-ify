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
    /* Use ONLY async-signal-safe functions. snprintf is NOT safe in a
     * signal handler — it can deadlock on the stdio lock. Use write()
     * with a fixed buffer and manual hex conversion. */
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

    /* Print first 8 stack entries */
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

    _exit(128 + sig);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
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
        if (macos_act->mask) {
            memcpy(&linux_act.sa_mask, &macos_act->mask, sizeof(uint32_t));
        }
        /* For SIGSEGV/SIGBUS: install OUR crash handler with SA_ONSTACK
         * so it runs on the alternate signal stack (set up in the constructor).
         * Without SA_ONSTACK, a stack overflow prevents the handler from
         * running because there's no stack space to push the signal frame. */
        if (signum == SIGSEGV || signum == SIGBUS) {
            linux_act.sa_sigaction = macify_crash_handler;
            linux_act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
        }
        p_linux_act = &linux_act;
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
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
        real_sigaction(signum, &sa, NULL);
        return SIG_DFL;
    }
    static sighandler_t (*real_signal)(int, sighandler_t) = NULL;
    if (!real_signal) real_signal = dlsym(RTLD_NEXT, "signal");
    return real_signal(signum, handler);
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

/* Expand a 4-byte macOS sigset to a 128-byte Linux sigset */
static void macos_to_linux_sigset(const void *macos_set, sigset_t *linux_set) {
    uint32_t macos_mask = *(const uint32_t *)macos_set;
    /* Use glibc's sigemptyset (not our override) to properly zero 128 bytes */
    static int (*real_sigemptyset)(sigset_t *) = NULL;
    if (!real_sigemptyset) real_sigemptyset = dlsym(RTLD_NEXT, "sigemptyset");
    real_sigemptyset(linux_set);
    for (int i = 1; i <= 31; i++) {
        if (macos_mask & (1u << (i - 1))) {
            /* Use glibc's sigaddset */
            static int (*real_sigaddset)(sigset_t *, int) = NULL;
            if (!real_sigaddset) real_sigaddset = dlsym(RTLD_NEXT, "sigaddset");
            real_sigaddset(linux_set, i);
        }
    }
}

/* Compress a 128-byte Linux sigset to a 4-byte macOS sigset */
static void linux_to_macos_sigset(const sigset_t *linux_set, void *macos_set) {
    uint32_t macos_mask = 0;
    static int (*real_sigismember)(const sigset_t *, int) = NULL;
    if (!real_sigismember) real_sigismember = dlsym(RTLD_NEXT, "sigismember");
    for (int i = 1; i <= 31; i++) {
        if (real_sigismember(linux_set, i)) {
            macos_mask |= (1u << (i - 1));
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

/* sigaltstack: the Rust runtime calls sigaltstack to set up its own alt
 * stack, which may be in a bad location (within the guard page area). We
 * no-op this call so our constructor's alt stack (set up via raw syscall)
 * remains active. Our alt stack is a 256KB static buffer in the shim,
 * which is always safe. */
int macify_sigaltstack(const stack_t *ss, stack_t *oss) __asm__("sigaltstack");
int macify_sigaltstack(const stack_t *ss, stack_t *oss) {
    if (oss) {
        /* Return our alt stack info as the "old" stack */
        oss->ss_sp = NULL;
        oss->ss_size = 0;
        oss->ss_flags = 0;
    }
    return 0;  /* pretend success, don't change the alt stack */
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
