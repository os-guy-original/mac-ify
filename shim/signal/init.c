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

    /* Map a zeroed page at 0xfbad2000 so that dereferencing glibc's _flags
     * (0xfbad2084 etc.) as a pointer returns 0 instead of SIGSEGV.
     *
     * macOS code's inlined getc/putc macros read _p (offset 0 of FILE*) as
     * an 8-byte pointer. On glibc, offset 0 is _flags (0xfbad2084). When
     * _IO_read_ptr (offset 8) is NULL, _p = 0x00000000fbad2084 = 0xfbad2084.
     * Dereferencing this crashes. By mapping 0xfbad2000-0xfbad2fff, the
     * dereference returns 0 (NUL byte) and _p++ stays within the page.
     *
     * This is a SAFETY NET — the __srget/fgetc/fread shims set _r = -1 to
     * prevent inlined getc from dereferencing _p. But if there's a window
     * where _r is positive (e.g., after fgetc but before _r is set), the
     * mmap prevents the crash. */
    {
        void *p = mmap((void *)0xfbad2000, 0x1000, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        (void)p;  /* if mapping fails, the SIGSEGV recovery handler is the fallback */
    }

    /* Allocate stdout's buffer at a controlled address where the low byte
     * does NOT have bit 0x40 set. macOS binaries check [stdout + 0x10] & 0x40
     * for __SERR (error flag). Glibc stores _IO_read_end (buffer pointer) at
     * offset 0x10. If the buffer address has bit 0x40 in its low byte, macOS
     * code falsely detects a write error.
     *
     * We use mmap to get a page at a predictable address, then use part of it
     * as stdout's buffer. Since most macOS binaries don't call setvbuf, our
     * buffer persists for the lifetime of the process. */
    {
        char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page && page != MAP_FAILED) {
            /* Check if the address has bit 0x40 set */
            if (((uintptr_t)page & 0x40) == 0) {
                /* Safe to use directly */
                setvbuf(stdout, page, _IOLBF, 4096);
            } else {
                /* Bit 0x40 is set — find an offset within the page that clears it */
                char *safe = (char *)(((uintptr_t)page + 0x40) & ~0x3f);
                if (((uintptr_t)safe & 0x40) == 0 && safe + 4096 <= page + 4096) {
                    setvbuf(stdout, safe, _IOLBF, 4096 - (safe - page));
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
    sa.flags = 0x0C000004;  /* SA_SIGINFO(0x4) | SA_ONSTACK(0x08000000) | SA_RESTORER(0x04000000) */
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
