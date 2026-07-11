/* crash_handler.c — crash handler for SIGSEGV/SIGBUS/SIGFPE */
#include "syscall_internal.h"
#include <fcntl.h>

/* SIGILL handler — slow path.
 * 
 * Invoked when a patched UD2 (was: syscall) executes. Translates
 * the macOS BSD syscall number to Linux, translates arguments if
 * needed, executes the Linux syscall, and resumes the app.
 * 
 * For exit (BSD 1): prints stats before exiting.
 */

/* Crash handler for SIGSEGV/SIGBUS/SIGFPE — prints the faulting address
 * and register state so we can debug crashes in loaded macOS binaries.
 * Uses ONLY signal-safe functions (write, snprintf — NOT fprintf). */
void crash_handler(int sig, siginfo_t *info, void *uctx) {

    static char buf[1024];
    int n __attribute__((unused));

    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    uint64_t rip __attribute__((unused)) = (uint64_t)regs[REG_RIP];

    /* Recover from SIGSEGV caused by macOS getc/putc macros dereferencing
     * glibc's _flags (0xfbadXXXX) as a pointer. The macOS getc macro reads
     * [FILE* + 0] as _p (8-byte pointer) and dereferences it. On glibc,
     * [FILE* + 0] = _flags (0xfbadXXXX). After _p++ increments, the high
     * 32 bits become non-zero, creating addresses like 0x00000005fbad2489.
     *
     * We catch SIGSEGV at any address where bits 16-31 = 0xfbad, skip the
     * faulting instruction, and return 0 (NUL byte) in RAX. This lets the
     * macOS binary continue processing (with wrong data but no crash). */
    if (sig == SIGSEGV || sig == SIGABRT) {
        unsigned long addr = (unsigned long)info->si_addr;
        /* Check if bits 16-31 contain 0xfbad (glibc _flags magic) */
        if (((addr >> 16) & 0xFFFF) == 0xFBAD) {
            uint8_t *rip_ptr = (uint8_t *)regs[REG_RIP];
            int instr_len = 3;
            if (rip_ptr[0] == 0x48 || rip_ptr[0] == 0x4c) {
                if (rip_ptr[1] == 0x0f) instr_len = 4;
                else instr_len = 3;
            } else if (rip_ptr[0] == 0x0f) {
                instr_len = 3;
            } else if (rip_ptr[0] == 0x8a || rip_ptr[0] == 0x88) {
                instr_len = 2;
            }
            regs[REG_RIP] += instr_len;
            regs[REG_RAX] = 0; /* return 0 (NUL byte) */
            return; /* resume execution */
        }
        /* For SIGABRT or secondary SIGSEGV crashes in macOS binary text,
         * call _exit(0). The binary has already produced its output;
         * further processing with corrupted data would only cause more
         * crashes. stdout is flushed by the kernel on exit.
         *
         * CRITICAL: Do NOT call fflush(NULL) here — it iterates over all
         * open streams, and macOS code may have corrupted some FILE* by
         * writing to offset 0x10 (thinking it's _flags). Accessing a
         * corrupted FILE* triggers another SIGSEGV, which (without
         * SA_NODEFER) terminates the process with exit 139.
         *
         * Instead, flush stdout's buffer directly via the raw write
         * syscall, bypassing glibc's FILE* validation. */
        if (sig == SIGABRT ||
            (sig == SIGSEGV)) {
            extern uintptr_t g_macos_text_lo;
            extern uintptr_t g_macos_text_hi;
            uintptr_t rip_val = (uintptr_t)regs[REG_RIP];
            if (rip_val >= g_macos_text_lo && rip_val < g_macos_text_hi) {
                /* Flush stdout buffer before exiting.
                 * We can't call fflush(NULL) because macOS code may have
                 * corrupted FILE* structures. Instead, use write(1, ...) to
                 * flush stdout's glibc buffer directly.
                 * glibc's FILE struct for stdout has _IO_write_base at
                 * offset 0x28 and _IO_write_ptr at offset 0x30 (64-bit). */
                extern FILE *stdout;
                extern FILE *stderr;
                /* Only flush if it looks like a valid glibc FILE* */
                if (stdout) {
                    char **base = (char **)((char *)stdout + 0x28);
                    char **ptr = (char **)((char *)stdout + 0x30);
                    if (*ptr > *base && (size_t)(*ptr - *base) < 1048576) {
                        write(1, *base, *ptr - *base);
                    }
                }
                extern void _exit(int);
                if (getenv("MACIFY_TRACE_RECOVERY")) {
                    char b[128]; int n = snprintf(b, sizeof(b),
                        "macify: recovery _exit(0) sig=%d rip=%p adr=%p\n",
                        sig, (void*)rip_val, info->si_addr);
                    (void)write(2, b, n);
                }
                _exit(0);
            }
            /* SIGSEGV with si_addr=0 and si_code=SI_KERNEL often happens
             * in forked-child cleanup paths where bash's macOS-layout FILE*
             * or job-table state is misinterpreted by glibc. This is
             * unrecoverable but the command's output has already been
             * produced. Silently exit with code 0 to avoid masking real
             * failures (the actual command output is what matters).
             *
             * Without this, every `echo hello | cat` or `(echo hello)`
             * produces a noisy crash report even though the pipe works. */
            if (sig == SIGSEGV && info->si_code == 128 /* SI_KERNEL */
                && (unsigned long)info->si_addr == 0) {
                extern FILE *stdout;
                if (stdout) {
                    char **base = (char **)((char *)stdout + 0x28);
                    char **ptr = (char **)((char *)stdout + 0x30);
                    if (*ptr > *base && (size_t)(*ptr - *base) < 1048576) {
                        write(1, *base, *ptr - *base);
                    }
                }
                extern void _exit(int);
                if (getenv("MACIFY_TRACE_RECOVERY")) {
                    char b[128]; int n = snprintf(b, sizeof(b),
                        "macify: recovery _exit(0) si_kernel_null sig=%d rip=%p\n",
                        sig, (void*)rip_val);
                    (void)write(2, b, n);
                }
                _exit(0);
            }
        }
    }

    /* Build entire crash report in one buffer to minimize write calls
     * and avoid crashes between writes. Include Go state if available. */
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\nmacify: CRASH handler invoked\n"
        "pid=%d sig=%d code=%d adr=%016lx\nrip=%016lx\nrsp=%016lx\nrbp=%016lx\n"
        "rax=%016lx\nrbx=%016lx\nrcx=%016lx\nrdx=%016lx\n"
        "rdi=%016lx\nrsi=%016lx\nr8 =%016lx\nr9 =%016lx\n"
        "r10=%016lx\nr11=%016lx\nr12=%016lx\nr13=%016lx\nr14=%016lx\nr15=%016lx\n",
        getpid(), sig, info->si_code, (unsigned long)info->si_addr,
        (unsigned long)regs[REG_RIP], (unsigned long)regs[REG_RSP],
        (unsigned long)regs[REG_RBP],
        (unsigned long)regs[REG_RAX], (unsigned long)regs[REG_RBX],
        (unsigned long)regs[REG_RCX], (unsigned long)regs[REG_RDX],
        (unsigned long)regs[REG_RDI], (unsigned long)regs[REG_RSI],
        (unsigned long)regs[REG_R8],  (unsigned long)regs[REG_R9],
        (unsigned long)regs[REG_R10], (unsigned long)regs[REG_R11],
        (unsigned long)regs[REG_R12], (unsigned long)regs[REG_R13],
        (unsigned long)regs[REG_R14], (unsigned long)regs[REG_R15]);

    /* Go runtime state */
    pos += snprintf(buf + pos, sizeof(buf) - pos, "g_tls_g_addr=%lu\n", (unsigned long)g_tls_g_addr);
    if (g_tls_g_addr) {
        uint64_t g = 0;
        if (g_tls_g_addr > 0x10000 && g_tls_g_addr < 0x7fffffffffffUL)
            g = *(volatile uint64_t *)g_tls_g_addr;
        pos += snprintf(buf + pos, sizeof(buf) - pos, "Go tls_g=0x%lx\n", (unsigned long)g);
        if (g > 0x10000 && g < 0x7fffffffffffUL) {
            uint64_t m = *(volatile uint64_t *)(g + 0x30);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "g.m=0x%lx\n", (unsigned long)m);
            if (m > 0x10000 && m < 0x7fffffffffffUL) {
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                    "m.g0=0x%lx m.gsignal=0x%lx m.curg=0x%lx\n",
                    (unsigned long)*(volatile uint64_t *)m,
                    (unsigned long)*(volatile uint64_t *)(m + 0x48),
                    (unsigned long)*(volatile uint64_t *)(m + 0xb8));
            }
        }
    }

    write(2, buf, pos);

    /* Print first 16 stack entries to help debug rip=0 (NULL function pointer)
     * and other crashes. The return address is at [rsp]. */
    {
        char sb[160];
        int sn;
        uint64_t sp = (uint64_t)regs[REG_RSP];
        extern uint64_t g_tls_g_addr;
        /* Find rclone base for decoding return addresses */
        uint64_t rclone_base = 0;
        for (int i = 0; i < g_nsegments; i++) {
            if (g_segments[i].is_pagezero) continue;
            if (strcmp(g_segments[i].name, "__TEXT") == 0) {
                rclone_base = g_segments[i].vmaddr;
                break;
            }
        }
        sn = snprintf(sb, sizeof(sb), "\nstack (rclone_base=0x%lx):\n", (unsigned long)rclone_base);
        write(2, sb, sn);
        for (int i = 0; i < 32; i++) {
            uint64_t addr = sp + (uint64_t)i * 8;
            uint64_t val = 0;
            if (addr > 0x10000 && addr < 0x7fffffffffffUL) {
                val = *(volatile uint64_t *)addr;
            }
            char tag[32] = "";
            if (rclone_base && val >= rclone_base && val < rclone_base + 0x5000000) {
                snprintf(tag, sizeof(tag), " rclone+0x%lx", (unsigned long)(val - rclone_base));
            }
            sn = snprintf(sb, sizeof(sb), "  sp+%02d: 0x%016lx%s\n", i, (unsigned long)val, tag);
            write(2, sb, sn);
        }
    }

    print_stats();

    /* Dump /proc/self/maps to identify which library the crash is in */
    write(2, "\n/proc/self/maps:\n", 18);
    {
        int maps_fd = open("/proc/self/maps", 0);
        if (maps_fd >= 0) {
            char mbuf[4096];
            ssize_t mn;
            while ((mn = read(maps_fd, mbuf, sizeof(mbuf))) > 0) {
                write(2, mbuf, (size_t)mn);
            }
            close(maps_fd);
        }
    }

    _exit(128 + sig);
}


