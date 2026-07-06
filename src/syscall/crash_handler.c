/* crash_handler.c — crash handler for SIGSEGV/SIGBUS/SIGFPE */
#include "syscall_internal.h"

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
    int n;

    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    uint64_t rip = (uint64_t)regs[REG_RIP];

    /* Build entire crash report in one buffer to minimize write calls
     * and avoid crashes between writes. Include Go state if available. */
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\nmacify: CRASH handler invoked\n"
        "sig=%d adr=%016lx\nrip=%016lx\nrsp=%016lx\nrbp=%016lx\n"
        "rax=%016lx\nrbx=%016lx\nrcx=%016lx\nrdx=%016lx\n"
        "rdi=%016lx\nrsi=%016lx\nr8 =%016lx\nr9 =%016lx\n"
        "r10=%016lx\nr11=%016lx\nr12=%016lx\nr13=%016lx\nr14=%016lx\nr15=%016lx\n",
        sig, (unsigned long)info->si_addr,
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
    _exit(128 + sig);
}

