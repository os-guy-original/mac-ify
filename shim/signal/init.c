/* init.c — constructor, signal stack setup, crash handler installation */
#include "signal_internal.h"
#include <sys/syscall.h>

/* Track the original PID to detect forked children.
 * Set in the constructor (parent process). After fork(), the child
 * inherits this value (parent's PID), so getpid() != g_original_pid
 * returns TRUE in the child. */
static pid_t g_original_pid = 0;

/* atfork child handler — currently a no-op.
 *
 * Previously this called _exit(0) to immediately kill forked children,
 * which completely broke pipes (echo hello | cat) and subshells because
 * every forked child died before it could exec the next command.
 *
 * We must NOT reset g_original_pid here — the child needs to keep the
 * parent's PID so is_forked_child() correctly returns TRUE in the
 * forked child. */
static void atfork_child_handler(void) {
    /* no-op — child inherits parent's g_original_pid */
}

void atfork_child_exit(void) {
    pthread_atfork(NULL, NULL, atfork_child_handler);
}

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
    /* Start with glibc's FILE structs. The macify loader will switch to
     * macOS FILE structs later (via macify_use_macos_stdio) if the binary
     * uses inlined putc macros (detected by text size > 100KB). */
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

    /* Allocate stdout's buffer at a LOW address (below 4GB) so that
     * _IO_read_ptr's upper 4 bytes (which overlap with macOS's _w at
     * offset 0x0c) are 0. With _w=0, the putc macro's `jg` (jump-if-
     * greater) won't take the fast path — it falls through to check
     * for '\n' and calls __swbuf, which we intercept.
     *
     * Also ensure the buffer address doesn't have bit 0x40 set in the
     * low byte (macOS __SERR false positive check at [fp+0x10]).
     *
     * We mmap at 0x10000 (64KB), which is:
     *   - Below 4GB (upper 4 bytes = 0 → _w = 0)
     *   - Bit 0x40 not set in low byte (0x00 & 0x40 = 0)
     *   - Page-aligned
     *   - Unlikely to conflict with other mappings */
    {
        char *buf = mmap((void *)0x10000, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (buf && buf != MAP_FAILED) {
            setvbuf(stdout, buf, _IOLBF, 4096);
        } else {
            /* Fallback: try any low address */
            for (uintptr_t addr = 0x20000; addr < 0x10000000; addr += 0x1000) {
                buf = mmap((void *)addr, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
                if (buf && buf != MAP_FAILED && (uintptr_t)buf < 0x100000000ULL) {
                    if (((uintptr_t)buf & 0x40) == 0) {
                        setvbuf(stdout, buf, _IOLBF, 4096);
                        break;
                    }
                    munmap(buf, 4096);
                }
            }
        }
        /* Same for stderr — use unbuffered so characters go through write() */
        char *ebuf = mmap((void *)0x11000, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (ebuf && ebuf != MAP_FAILED) {
            setvbuf(stderr, ebuf, _IONBF, 0);
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
