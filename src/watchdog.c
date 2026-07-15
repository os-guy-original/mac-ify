/* watchdog.c — SIGALRM-based hang detector.
 *
 * When the macOS binary hangs (e.g., on a futex deadlock), this watchdog
 * fires after a configurable timeout and dumps:
 *   - Current RIP, RSP, RBP (from ucontext)
 *   - Which module RIP belongs to (macOS text, shim, libc, or unknown)
 *   - A backtrace (best-effort, using rbp chain + glibc backtrace)
 *   - All loaded modules and their address ranges
 *   - The macOS binary's segment map
 *   - /proc/self/maps (to match futex addresses to modules)
 *
 * Enable with: MACIFY_WATCHDOG=3  (3-second timeout)
 * The dump goes to stderr (fd 2) using only write() — no stdio, no malloc,
 * because those might be deadlocked too. */
#include "macify.h"
#include <execinfo.h>
#include <sys/time.h>

/* Watchdog state — set before arming. */
static int macify_watchdog_armed = 0;

/* Write a string to stderr using raw write() — no stdio buffering. */
static void wd_write(const char *s) {
    (void)write(2, s, strlen(s));
}

static void wd_hex(const char *prefix, uint64_t val) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%s0x%lx", prefix, (unsigned long)val);
    (void)write(2, buf, n);
}

/* Describe an address: which module does it belong to?
 * Uses g_segments (macOS binary) and g_macho_dylibs (Mach-O dylibs).
 * For ELF modules (libc, shim, etc.), we rely on /proc/self/maps. */
static void wd_describe_addr(uint64_t addr) {
    extern loaded_segment g_segments[];
    extern int g_nsegments;
    extern macho_dylib g_macho_dylibs[];
    extern int g_n_macho_dylibs;

    /* Check macOS binary segments */
    for (int i = 0; i < g_nsegments; i++) {
        uint64_t lo = g_segments[i].vmaddr;
        uint64_t hi = lo + g_segments[i].vmsize;
        if (addr >= lo && addr < hi) {
            char buf[256];
            int n = snprintf(buf, sizeof(buf),
                "  -> in macOS binary %s segment [0x%lx, 0x%lx)\n",
                g_segments[i].name, (unsigned long)lo, (unsigned long)hi);
            (void)write(2, buf, n);
            return;
        }
    }
    /* Check Mach-O dylibs — we don't have the mapped base stored directly,
     * but we can check the first export address as a proxy. Skip for now
     * and rely on /proc/self/maps for dylib address matching. */
    (void)g_macho_dylibs;
    (void)g_n_macho_dylibs;

    {
        char buf[128];
        int n = snprintf(buf, sizeof(buf),
            "  -> addr 0x%lx (check /proc/self/maps below)\n",
            (unsigned long)addr);
        (void)write(2, buf, n);
    }
}

/* Backtrace using the signal context's RSP/RIP. */
static void wd_backtrace_from_context(ucontext_t *uc) {
    wd_write("\n=== BACKTRACE (from signal context) ===\n");

    uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    uint64_t rsp = uc->uc_mcontext.gregs[REG_RSP];
    uint64_t rbp = uc->uc_mcontext.gregs[REG_RBP];

    wd_write("  RIP="); wd_hex("", rip); wd_describe_addr(rip);
    wd_write("  RSP="); wd_hex("", rsp); wd_write("\n");
    wd_write("  RBP="); wd_hex("", rbp); wd_write("\n");

    /* Walk frame pointers — macOS binaries use standard rbp chains.
     * Each frame: [rbp] = saved rbp, [rbp+8] = return addr. */
    wd_write("\n  Frame walk (rbp chain):\n");
    uint64_t cur_rbp = rbp;
    int depth = 0;
    while (cur_rbp && depth < 64) {
        /* Read [rbp] = next rbp, [rbp+8] = return addr.
         * These might fault if the stack is corrupted, but we're in
         * a signal handler so a fault would just crash — acceptable
         * for diagnostics. */
        volatile uint64_t *p = (volatile uint64_t *)cur_rbp;
        uint64_t next_rbp = p[0];
        uint64_t ret_addr = p[1];

        if (!ret_addr) break;

        char buf[32];
        int n = snprintf(buf, sizeof(buf), "  #%d  ret=", depth);
        (void)write(2, buf, n);
        wd_hex("", ret_addr);
        wd_describe_addr(ret_addr);

        if (next_rbp <= cur_rbp) break; /* prevent infinite loop */
        cur_rbp = next_rbp;
        depth++;
    }

    /* Also try glibc's backtrace() which uses .eh_frame — may work for
     * the Linux-side frames (macify, shim, libc). */
    wd_write("\n  glibc backtrace() (Linux-side frames):\n");
    void *bt[32];
    int n_bt = backtrace(bt, 32);
    for (int i = 0; i < n_bt; i++) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf), "  #%d  %p", i, bt[i]);
        (void)write(2, buf, n);
        wd_describe_addr((uint64_t)(uintptr_t)bt[i]);
    }
}

/* Dump /proc/self/maps to show ALL memory regions — this lets us
 * match the futex address to a specific module. */
static void wd_dump_maps(void) {
    wd_write("\n=== /proc/self/maps ===\n");
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        wd_write("  (cannot open /proc/self/maps)\n");
        return;
    }
    char buf[8192];
    ssize_t n;
    int total = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0 && total < 65536) {
        (void)write(2, buf, n);
        total += n;
    }
    close(fd);
}

/* Dump the macOS binary's segments (from our loader state). */
static void wd_dump_segments(void) {
    extern loaded_segment g_segments[];
    extern int g_nsegments;
    wd_write("\n=== macOS binary segments ===\n");
    for (int i = 0; i < g_nsegments; i++) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf), "  %-16s  0x%lx + 0x%-6lx  prot=%d\n",
                g_segments[i].name,
                (unsigned long)g_segments[i].vmaddr,
                (unsigned long)g_segments[i].vmsize,
                g_segments[i].prot);
        (void)write(2, buf, n);
    }
}

/* The watchdog signal handler. */
static void macify_watchdog_handler(int sig, siginfo_t *info, void *uctx) {
    (void)sig;
    (void)info;

    if (!macify_watchdog_armed) return;
    macify_watchdog_armed = 0;

    wd_write("\n"
             "========================================\n"
             " macify WATCHDOG: process appears hung!\n"
             "========================================\n");

    ucontext_t *uc = (ucontext_t *)uctx;
    wd_backtrace_from_context(uc);
    wd_dump_segments();
    wd_dump_maps();

    wd_write("\n=== END WATCHDOG DUMP ===\n");

    /* Exit with a distinctive code so the user knows the watchdog fired. */
    _exit(233);
}

/* Arm the watchdog. Called just before jumping to the macOS binary's main().
 * The timeout is read from MACIFY_WATCHDOG env var (seconds, default disabled). */
void macify_arm_watchdog(void) {
    const char *env = getenv("MACIFY_WATCHDOG");
    if (!env || !*env) return;

    int timeout = atoi(env);
    if (timeout <= 0) return;

    /* Install our handler for SIGALRM.
     * We DON'T use SA_ONSTACK because we want to run on the current
     * stack (the macOS binary's stack), not the sigaltstack. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = macify_watchdog_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        wd_write("macify: WARNING: failed to install watchdog handler\n");
        return;
    }

    /* Unblock SIGALRM */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    macify_watchdog_armed = 1;

    /* Set the timer. */
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = timeout;
    setitimer(ITIMER_REAL, &it, NULL);

    if (g_verbose) {
        char buf[64];
        int n = snprintf(buf, sizeof(buf),
            "macify: watchdog armed (%d second timeout)\n", timeout);
        (void)write(2, buf, n);
    }
}
