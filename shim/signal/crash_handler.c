/* crash_handler.c — crash handler that prints register/stack/Go state */
#include "signal_internal.h"
#include <ucontext.h>

void macify_crash_handler(int sig, siginfo_t *info, void *uctx) {
    const char msg[] = "\nmacify: CRASH handler invoked\n";
    write(2, msg, sizeof(msg) - 1);

    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    /* Print first 8 stack entries IMMEDIATELY */
    {
        char sb[256];
        int sn = 0;
        uint64_t sp = (uint64_t)regs[REG_RSP];
        sn = snprintf(sb, sizeof(sb), "rsp=0x%lx stack:", (unsigned long)sp);
        write(2, sb, sn);
        for (int i = 0; i < 8; i++) {
            uint64_t val = 0;
            if (sp + i*8 > 0x10000 && sp + i*8 < 0x7fffffffffffUL) {
                val = *(volatile uint64_t *)(sp + i*8);
            }
            sn = snprintf(sb, sizeof(sb), " 0x%016lx", (unsigned long)val);
            write(2, sb, sn);
        }
        write(2, "\n", 1);
    }

    /* Check signal stack validity */
    stack_t cur_ss;
    memset(&cur_ss, 0, sizeof(cur_ss));
    syscall(131, NULL, &cur_ss);
    char ss_buf[128];
    int ss_n = snprintf(ss_buf, sizeof(ss_buf),
        "sigaltstack: sp=%p size=%zu flags=0x%x (ONSTACK=%d DISABLE=%d)\n",
        cur_ss.ss_sp, cur_ss.ss_size, cur_ss.ss_flags,
        (cur_ss.ss_flags & 1) ? 1 : 0,
        (cur_ss.ss_flags & 2) ? 1 : 0);
    write(2, ss_buf, ss_n);

    char buf[128];

    /* Write signal number, fault address, and si_code */
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
    buf[28] = ' ';
    buf[29] = 'c'; buf[30] = 'o'; buf[31] = 'd'; buf[32] = 'e'; buf[33] = '=';
    int code = info->si_code;
    buf[34] = '0' + (code / 100) % 10;
    buf[35] = '0' + (code / 10) % 10;
    buf[36] = '0' + code % 10;
    buf[37] = '\n';
    write(2, buf, 38);

    /* Print registers */
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

    /* Print stack entries or Go runtime state */
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
        /* Go binary: print runtime state */
        uint64_t gs_val = 0;
        __asm__ volatile("movq %%gs:0x30, %0" : "=r"(gs_val));
        write(2, "gs:0x30=", 8);
        for (int i = 0; i < 16; i++) {
            int nibble = (gs_val >> (60 - i*4)) & 0xf;
            buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
        }
        buf[16] = '\n';
        write(2, buf, 17);

        uint64_t fs_val = 0;
        __asm__ volatile("movq %%fs:0x30, %0" : "=r"(fs_val));
        write(2, "fs:0x30=", 8);
        for (int i = 0; i < 16; i++) {
            int nibble = (fs_val >> (60 - i*4)) & 0xf;
            buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
        }
        buf[16] = '\n';
        write(2, buf, 17);

        uint64_t g = 0;
        if (g_tls_g_addr > 0x10000 && g_tls_g_addr < 0x7fffffffffffUL)
            g = *(volatile uint64_t *)g_tls_g_addr;
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

            int32_t mlocks = *(volatile int32_t *)(m + 0x108);
            write(2, "m.locks=", 8);
            char lb[24]; int ln = 0;
            if (mlocks < 0) { lb[ln++] = '-'; mlocks = -mlocks; }
            char tmp[12]; int tn = 0;
            if (mlocks == 0) tmp[tn++] = '0';
            while (mlocks > 0) { tmp[tn++] = '0' + (mlocks % 10); mlocks /= 10; }
            while (tn > 0) lb[ln++] = tmp[--tn];
            lb[ln++] = '\n';
            write(2, lb, ln);

            /* Print key m offsets */
            {
                char mbuf[256]; int mn = 0;
                uint64_t m48 = *(volatile uint64_t *)(m + 0x48);
                uint64_t m50 = *(volatile uint64_t *)(m + 0x50);
                uint64_t m58 = *(volatile uint64_t *)(m + 0x58);
                uint64_t m60 = *(volatile uint64_t *)(m + 0x60);
                mn = snprintf(mbuf, sizeof(mbuf),
                    "m+48=0x%lx m+50=0x%lx m+58=0x%lx m+60=0x%lx\n",
                    (unsigned long)m48, (unsigned long)m50,
                    (unsigned long)m58, (unsigned long)m60);
                write(2, mbuf, mn);

                uint64_t candidates[] = {m48, m50, m58, m60};
                int offsets[] = {0x48, 0x50, 0x58, 0x60};
                for (int i = 0; i < 4; i++) {
                    uint64_t gsig = candidates[i];
                    if (gsig > 0x10000 && gsig < 0x7fffffffffffUL) {
                        uint64_t slo = *(volatile uint64_t *)(gsig + 0x0);
                        uint64_t shi = *(volatile uint64_t *)(gsig + 0x8);
                        mn = snprintf(mbuf, sizeof(mbuf),
                            "  m+0x%02x as gsignal: g=%p stack.lo=0x%lx hi=0x%lx (size=%ld)\n",
                            offsets[i], (void*)gsig,
                            (unsigned long)slo, (unsigned long)shi,
                            (long)(shi - slo));
                        write(2, mbuf, mn);
                    }
                }
            }

            /* Print g0.stack info */
            uint64_t stacklo = *(volatile uint64_t *)(g + 0x0);
            uint64_t stackhi = *(volatile uint64_t *)(g + 0x8);
            uint64_t stackguard0 = *(volatile uint64_t *)(g + 0x10);
            uint64_t stackguard1 = *(volatile uint64_t *)(g + 0x18);
            uint64_t cur_rsp = (uint64_t)regs[REG_RSP];
            char sb[256];
            int sn = snprintf(sb, sizeof(sb),
                "g.stack: lo=0x%lx hi=0x%lx guard0=0x%lx guard1=0x%lx rsp=0x%lx (overflow=%d)\n",
                (unsigned long)stacklo, (unsigned long)stackhi,
                (unsigned long)stackguard0, (unsigned long)stackguard1,
                (unsigned long)cur_rsp, cur_rsp <= stackguard0);
            write(2, sb, sn);

            if (gsignal > 0x10000 && gsignal < 0x7fffffffffffUL) {
                uint64_t gs_stacklo = *(volatile uint64_t *)(gsignal + 0x0);
                uint64_t gs_stackhi = *(volatile uint64_t *)(gsignal + 0x8);
                uint64_t gs_guard0 = *(volatile uint64_t *)(gsignal + 0x10);
                sn = snprintf(sb, sizeof(sb),
                    "gsignal.stack: lo=0x%lx hi=0x%lx guard0=0x%lx (size=%ld)\n",
                    (unsigned long)gs_stacklo, (unsigned long)gs_stackhi,
                    (unsigned long)gs_guard0,
                    (long)(gs_stackhi - gs_stacklo));
                write(2, sb, sn);
            }
        }

        /* Print stack dump */
        write(2, "stack:\n", 7);
        uint64_t sp_val = (uint64_t)regs[REG_RSP];
        for (int s = -8; s < 24; s++) {
            uint64_t addr = sp_val + (int64_t)s * 8;
            if (addr < 0x10000 || addr > 0x7fffffffffffUL) continue;
            uint64_t val = *(volatile uint64_t *)addr;
            char marker[8];
            if (s < 0) {
                marker[0]='s';marker[1]='p';marker[2]='-';
                marker[3] = (-s) < 10 ? '0'+(-s) : 'a'+(-s)-10;
                marker[4]=':';marker[5]=' ';
            } else if (s == 0) {
                marker[0]='s';marker[1]='p';marker[2]='+';marker[3]='0';
                marker[4]=':';marker[5]=' ';
            } else {
                int ss = s;
                marker[0]='s';marker[1]='p';marker[2]='+';
                marker[3] = (ss/10) ? '0'+(ss/10) : '0';
                marker[4] = '0'+(ss%10);
                marker[5]=':';marker[6]=' ';
            }
            write(2, marker, 6);
            for (int i = 0; i < 16; i++) {
                int nibble = (addr >> (60 - i*4)) & 0xf;
                buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            buf[16] = ':'; buf[17] = ' ';
            write(2, buf, 18);
            for (int i = 0; i < 16; i++) {
                int nibble = (val >> (60 - i*4)) & 0xf;
                buf[i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
            }
            buf[16] = '\n';
            write(2, buf, 17);
        }
    }

    /* Dump /proc/self/maps */
    write(2, "maps:\n", 6);
    int maps_fd = open("/proc/self/maps", 0);
    if (maps_fd >= 0) {
        char mbuf[4096];
        ssize_t mn;
        while ((mn = read(maps_fd, mbuf, sizeof(mbuf))) > 0) {
            write(2, mbuf, mn);
        }
        close(maps_fd);
    }

    _exit(128 + sig);
}
