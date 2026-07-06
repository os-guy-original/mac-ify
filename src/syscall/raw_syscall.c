/* raw_syscall.c — raw syscall helper and stats printing */
#include "syscall_internal.h"

/* Raw syscall — bypasses glibc's errno translation. */

long raw_syscall(long nr, long a1, long a2, long a3,
                                long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}


/* Stats printing */

void print_stats(void) {
    if (g_stats_printed) return;
    g_stats_printed = true;
    fprintf(stderr, "\nmacify: stats:\n");
    fprintf(stderr, "         slow-path SIGILL invocations: %lu\n", g_slow_path_calls);
    fprintf(stderr, "         fast-path syscall sites:      %lu  (patched at load)\n",
            g_fast_path_sites);
    fprintf(stderr, "         slow-path syscall sites:      %lu  (patched at load)\n",
            g_slow_path_sites);
}


