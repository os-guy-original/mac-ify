/* init.c — constructor, signal stack setup, crash handler installation */
#include "signal_internal.h"
#include <sys/syscall.h>

/* atfork child handler: immediately exit forked children. */
static void atfork_child_handler(void) {
    _exit(0);
}

void atfork_child_exit(void) {
    pthread_atfork(NULL, NULL, atfork_child_handler);
}

/* Track the original PID to detect forked children. */
static pid_t g_original_pid = 0;

int is_forked_child(void) {
    if (g_original_pid == 0) g_original_pid = getpid();
    return getpid() != g_original_pid;
}

/* Cached glibc signal restorer function — needed for SA_RESTORER flag. */
void (*macify_sa_restorer)(void) = NULL;

/* Our own signal restorer function — calls rt_sigreturn syscall. */
__attribute__((naked))
void macify_restore_rt(void) {
    __asm__ volatile(
        "mov $15, %%rax\n\t"    /* SYS_rt_sigreturn = 15 */
        "syscall\n\t"
        :::
    );
}

/* Constructor to initialize the stdio pointers and signal handling. */
__attribute__((constructor))
static void macify_init_stdio(void) {
    __stderrp = stderr;
    __stdinp = stdin;
    __stdoutp = stdout;

    /* Ensure stdout's buffer address doesn't have bit 0x40 in its low byte.
     * macOS binaries check [stdout + 0x10] & 0x40 for __SERR (error flag).
     * Glibc stores _IO_read_end (buffer pointer) at offset 0x10. If the
     * buffer address has bit 0x40 set, macOS code falsely detects a write
     * error. By forcing a buffer write early, we can check and fix the
     * pointer. */
    {
        /* Force buffer allocation by writing nothing (just trigger setup) */
        char *buf = (char *)malloc(4096);
        if (buf) {
            /* Check if the buffer address has bit 0x40 set */
            if (((uintptr_t)buf & 0x40) == 0) {
                /* Safe to use — set as stdout's buffer */
                setvbuf(stdout, buf, _IOLBF, 4096);
            } else {
                /* Bit 0x40 is set — free and try again with a different size */
                free(buf);
                /* Allocate with a small offset to change the address */
                char *buf2 = (char *)malloc(4096 + 128);
                if (buf2) {
                    /* Use an offset that clears bit 0x40 */
                    char *aligned = (char *)(((uintptr_t)buf2 + 0x40) & ~0x3f);
                    if (((uintptr_t)aligned & 0x40) == 0) {
                        setvbuf(stdout, aligned, _IOLBF, 4096);
                    } else {
                        free(buf2);
                    }
                }
            }
        }
    }

    /* Initialize real_dlsym EARLY */
    extern void macify_init_real_dlsym(void);
    macify_init_real_dlsym();

    /* Cache glibc's signal restorer function for SA_RESTORER */
    static int (*real_sa)(int, const struct sigaction *, struct sigaction *) = NULL;
    if (!real_sa && real_dlsym) real_sa = real_dlsym(RTLD_NEXT, "sigaction");
    if (real_sa) {
        struct sigaction probe;
        memset(&probe, 0, sizeof(probe));
        probe.sa_handler = SIG_DFL;
        probe.sa_flags = SA_SIGINFO;
        sigemptyset(&probe.sa_mask);
        struct sigaction old;
        real_sa(SIGUSR1, &probe, &old);
        macify_sa_restorer = probe.sa_restorer;
        real_sa(SIGUSR1, &old, NULL);
    }
    if (!macify_sa_restorer) {
        macify_sa_restorer = macify_restore_rt;
    }

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

    /* Allocate a dedicated signal stack (256KB) */
    static char sigstack[256 * 1024] __attribute__((aligned(4096)));
    for (size_t i = 0; i < sizeof(sigstack); i += 4096) {
        sigstack[i] = 0;
    }
    stack_t ss;
    ss.ss_sp = sigstack;
    ss.ss_size = sizeof(sigstack);
    ss.ss_flags = 0;
    syscall(131, &ss, NULL);  /* sigaltstack */

    /* Install crash handler via raw rt_sigaction syscall */
    struct k_sigaction {
        void (*handler)(int, siginfo_t *, void *);
        unsigned long flags;
        void (*restorer)(void);
        unsigned long mask[16];
    };
    struct k_sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.handler = macify_crash_handler;
    sa.flags = 0x09000004;  /* SA_SIGINFO | SA_ONSTACK | SA_RESTORER */
    sa.restorer = macify_sa_restorer ? macify_sa_restorer : macify_restore_rt;
    memset(sa.mask, 0xff, sizeof(sa.mask));
    long r;
    r = syscall(13, 11, &sa, NULL, 8);  /* SIGSEGV */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGSEGV failed: %ld\n",r); write(2,b,n); }
    r = syscall(13, 7,  &sa, NULL, 8);  /* SIGBUS */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGBUS failed: %ld\n",r); write(2,b,n); }
    r = syscall(13, 6,  &sa, NULL, 8);  /* SIGABRT */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGABRT failed: %ld\n",r); write(2,b,n); }
    r = syscall(13, 8,  &sa, NULL, 8);  /* SIGFPE */
    if (r) { char b[64]; int n=snprintf(b,sizeof(b),"sigaction SIGFPE failed: %ld\n",r); write(2,b,n); }

    atfork_child_exit();
}
