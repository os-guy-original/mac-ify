#include "macify.h"
#include <sys/utsname.h>
#include <stdlib.h>


/* Stack setup — build the macOS-style entry stack:
 *   [argc] [argv[0..argc-1]] [NULL] [envp[0..n-1]] [NULL] [apple[0]] [NULL]
 */

uint64_t setup_stack(int argc, char **argv, char **envp, void **out_stack_base, size_t *out_stack_size) {
    /* Stack size: 8MB is enough for most binaries. Go binaries need more
     * because Go's runtime sets g0's stack to (rsp - 0x10000) and uses
     * deep recursion during init. We try 64MB first, then fall back. */
    size_t stack_size = 64 * 1024 * 1024;
    void *stack = mmap(NULL, stack_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        stack_size = 8 * 1024 * 1024;
        stack = mmap(NULL, stack_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (stack == MAP_FAILED) { perror("mmap stack"); exit(1); }

    /* Export stack base/size so the loader can pass it to the shim via
     * __macify_set_stack_info(). The shim's pthread_get_stackaddr_np
     * returns this instead of glibc's (wrong) main-thread stack info. */
    if (out_stack_base) *out_stack_base = stack;
    if (out_stack_size) *out_stack_size = stack_size;

    uint64_t top = (uint64_t)(uintptr_t)stack + stack_size;
    top &= ~0xFULL;

    int nenv = 0;
    for (char **e = envp; *e; e++) nenv++;

    size_t str_space = 0;
    for (int i = 0; i < argc; i++) str_space += strlen(argv[i]) + 1;
    for (int i = 0; i < nenv; i++) str_space += strlen(envp[i]) + 1;
    str_space += strlen(argv[0]) + 1;

    top -= str_space;
    top &= ~0xFULL;

    uint8_t *str = (uint8_t *)top;
    uint64_t *argv_ptrs = (argc > 0 && argc < 1000000) ? calloc((size_t)argc, sizeof(uint64_t)) : NULL;
    uint64_t *envp_ptrs = calloc((size_t)nenv + 1, sizeof(uint64_t));
    if (!argv_ptrs || !envp_ptrs) {
        fprintf(stderr, "macify: out of memory in setup_stack\n");
        exit(1);
    }

    for (int i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]) + 1;
        memcpy(str, argv[i], len);
        argv_ptrs[i] = (uint64_t)(uintptr_t)str;
        str += len;
    }
    for (int i = 0; i < nenv; i++) {
        size_t len = strlen(envp[i]) + 1;
        memcpy(str, envp[i], len);
        envp_ptrs[i] = (uint64_t)(uintptr_t)str;
        str += len;
    }
    uint64_t apple0 = (uint64_t)(uintptr_t)str;
    memcpy(str, argv[0], strlen(argv[0]) + 1);

    size_t ptr_count = 1 + (argc + 1) + (nenv + 1) + 2;
    top -= ptr_count * 8;
    top &= ~0xFULL;

    uint64_t *p = (uint64_t *)top;
    *p++ = (uint64_t)argc;
    for (int i = 0; i < argc; i++) *p++ = argv_ptrs[i];
    *p++ = 0;
    for (int i = 0; i < nenv; i++) *p++ = envp_ptrs[i];
    *p++ = 0;
    *p++ = apple0;
    *p++ = 0;

    free(argv_ptrs);
    free(envp_ptrs);

    if (g_verbose) {
        fprintf(stderr, "macify: stack at %#lx, argc=%d, nenv=%d\n",
                (unsigned long)top, argc, nenv);
    }
    return top;
}

/* Entry jump — set rsp and jmp to entry. Never returns. */
__attribute__((noreturn))
void jump_to_entry(uint64_t entry, uint64_t stack_top) {
    __asm__ volatile (
        "mov %[stk], %%rsp\n\t"
        "xor %%rbp, %%rbp\n\t"
        "jmp *%[rip]\n\t"
        :
        : [stk] "r"(stack_top), [rip] "r"(entry)
        : "memory"
    );
    __builtin_unreachable();
}


/* call_main_and_exit — for binaries with LC_MAIN (instead of LC_UNIXTHREAD).
 * The entry point is main(), a normal C function:
 *   int main(int argc, char **argv, char **envp, char **apple)
 *
 * Set up the stack, load arguments per the System V AMD64 ABI
 * (rdi=argc, rsi=argv, rdx=envp, rcx=apple), call main(), then exit_group()
 * with the return value. Compare jump_to_entry() which just jumps to a
 * LC_UNIXTHREAD entry point and lets the binary call exit() itself.
 */

/* Go binaries use %gs segment for thread-local storage (goroutine pointer
 * at gs:0x30, etc.). On macOS, the kernel sets up %gs base during thread
 * creation. On Linux, %gs base is 0 by default, so Go crashes on the first
 * gs:0x30 access.
 *
 * Go's rt0_go entry point tests GS by:
 *   1. Writing 0x123 to gs:0x30
 *   2. Reading a global variable (tls_g) that should be at gs:0x30
 *   3. Comparing — if they match, GS base is correct
 *
 * For this test to pass, GS base must be set to (tls_g_addr - 0x30).
 * We scan the entry point for the test pattern to find tls_g's address. */
#include <sys/syscall.h>

/* Pattern: mov qword ptr gs:[0x30], 0x123
 * Bytes: 65 48 c7 04 25 30 00 00 00 23 01 00 00
 * Followed by: mov rax, [rip + disp32]
 * Bytes: 48 8b 05 XX XX XX XX */
static const uint8_t gs_test_pattern[] = {
    0x65, 0x48, 0xc7, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x23, 0x01, 0x00, 0x00
};

static void setup_gs_base(uint64_t entry_rip) {
    /* Scan the first 0x400 bytes of the entry point for the GS test pattern */
    uint8_t *code = (uint8_t *)entry_rip;
    uint64_t tls_g_addr = 0;

    for (unsigned int i = 0; i < 0x400 - sizeof(gs_test_pattern) - 7; i++) {
        if (memcmp(code + i, gs_test_pattern, sizeof(gs_test_pattern)) == 0) {
            /* Found the pattern. Next instruction should be: mov rax, [rip + disp32]
             * 48 8b 05 XX XX XX XX (7 bytes) */
            uint8_t *next = code + i + sizeof(gs_test_pattern);
            if (next[0] == 0x48 && next[1] == 0x8b && next[2] == 0x05) {
                int32_t disp = *(int32_t *)(next + 3);
                /* RIP-relative: target = address_of_next_instruction + disp
                 * next_instruction = entry_rip + i + sizeof(gs_test_pattern) + 7 */
                uint64_t next_insn_addr = entry_rip + i + sizeof(gs_test_pattern) + 7;
                tls_g_addr = next_insn_addr + disp;
                break;
            }
        }
    }

    if (tls_g_addr) {
        /* Set GS base so that gs:0x30 points to tls_g.
         *
         * CRITICAL: On kernels < 5.15, using wrgsbase is unsafe because the
         * kernel's signal delivery code doesn't properly save/restore the
         * FSGSBASE-set GS base. When a signal arrives, the kernel restores
         * the SHADOW GS base (set by arch_prctl), not the wrgsbase value.
         * This causes Go's tls_g reads to return garbage after signal delivery,
         * leading to "morestack on g0" and "lock count" panics.
         *
         * On kernel 5.15+, the kernel properly handles FSGSBASE in signal
         * delivery, so wrgsbase is safe. We detect the kernel version and
         * only use wrgsbase on 5.15+.
         *
         * On older kernels, we use ONLY arch_prctl(ARCH_SET_GS), which goes
         * through the kernel and properly sets both the CPU register and the
         * shadow. This is slower but reliable. */
        uint64_t gs_base = tls_g_addr - 0x30;

        /* Set GS base using ONLY arch_prctl (not wrgsbase).
         * On kernel 5.10, wrgsbase causes rip=0 crashes (likely due to
         * kernel not properly saving/restoring FSGSBASE during signals). */
        syscall(158, 0x1001, gs_base);  /* ARCH_SET_GS */

        if (g_verbose) {
            /* Verify GS base was set correctly */
            uint64_t verify = 0;
            syscall(158, 0x1004, (uint64_t)&verify);  /* ARCH_GET_GS */
            fprintf(stderr, "macify: setup_gs_base: tls_g=0x%lx gs_base=0x%lx (wrgsbase=%d) verify=0x%lx %s\n",
                    (unsigned long)tls_g_addr, (unsigned long)gs_base, 1,
                    (unsigned long)verify,
                    verify == gs_base ? "OK" : "MISMATCH!");
        }
        g_tls_g_addr = tls_g_addr;
    } else {
        /* Not a Go binary (no GS test pattern found).
         * Set GS base to a zeroed page as a safe default. */
        static char gs_page[4096] __attribute__((aligned(4096)));
        memset(gs_page, 0, sizeof(gs_page));
        syscall(158, 0x1001, gs_page);
    }
}

__attribute__((noreturn))
void call_main_and_exit(uint64_t entry, uint64_t stack_top) {
    /* Set up %gs base for Go binaries that use gs:0x30 for goroutine TLS.
     * For Go binaries, GS base is set to (tls_g_addr - 0x30) so the GS
     * test in rt0_go passes. For non-Go binaries, a zeroed page is used. */
    setup_gs_base(entry);

    /* Map the macOS "comm page" at 0x7fffffe00000.
     * On macOS, the kernel maps a read-only page at 0x7fffffe00000 containing
     * system info (time, CPU info, etc.). Go's runtime reads from this page
     * (e.g., at offset 0x1e to check the macOS version).
     * On Linux, this page doesn't exist, so Go crashes with SIGSEGV.
     * We map a zeroed page at this address. Go's checks (like cmp ax, 0x0d)
     * will see 0 and take the appropriate branch. */
    void *comm_page = mmap((void *)0x7fffffe00000, 0x1000,
                           PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                           -1, 0);
    if (comm_page == MAP_FAILED && g_verbose) {
        /* If mapping failed (e.g., address in use), try without NOREPLACE */
        comm_page = mmap((void *)0x7fffffe00000, 0x1000,
                         PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                         -1, 0);
    }
    if (g_verbose) {
        fprintf(stderr, "macify: comm page at 0x7fffffe00000 = %p\n", comm_page);
    }

    /* For Go binaries: disable async preemption and block SIGURG.
     *
     * Async preemption (SIGURG-based) doesn't work reliably through our
     * signal translation layer. Go's sigtrampgo handler accesses g.m via
     * gs:0x30, and our signal wrapper's GS base management can conflict
     * with the kernel's signal delivery on kernel 5.10.
     *
     * Setting GODEBUG=asyncpreemptoff=1 tells Go to use cooperative
     * preemption only (safe points), which works correctly.
     *
     * We also block SIGURG initially to prevent signals from arriving
     * before Go's runtime is ready. Go will unblock it later (but since
     * async preempt is off, SIGURG won't be used for preemption).
     *
     * CRITICAL: Use memset + raw syscall, NOT sigemptyset/sigaddset/sigprocmask.
     * Our shim's overrides write only 4 bytes for macOS callers. */
    if (g_tls_g_addr) {
        /* GODEBUG=asyncpreemptoff=1 and GOMAXPROCS=1 are set in main.c
         * before setup_stack, so Go sees them in envp. */

        sigset_t go_mask;
        memset(&go_mask, 0, sizeof(go_mask));
        /* Set bit for SIGURG (signal 23, bit 22 in sigset) */
        unsigned long *bits = (unsigned long *)&go_mask;
        bits[22 / (sizeof(unsigned long) * 8)] |= (1UL << (22 % (sizeof(unsigned long) * 8)));
        /* Use raw syscall to bypass our shim's sigprocmask override */
        syscall(14, 0 /*SIG_BLOCK*/, &go_mask, NULL, sizeof(go_mask));
        if (g_verbose) {
            fprintf(stderr, "macify: Go binary — blocking SIGURG, async preempt off\n");
        }
    }

    /* Re-install crash handlers before calling main.
     * CRITICAL: Do NOT use SA_ONSTACK for non-Go binaries. SA_ONSTACK makes
     * the kernel run the handler on the sigaltstack. But if the macOS binary
     * corrupted the sigaltstack (e.g., via stack overflow or mmap collision),
     * the kernel can't push the signal frame → double fault → exit 139
     * without entering the handler.
     * Without SA_ONSTACK, the handler runs on the current stack (the macOS
     * binary's 64MB stack), which is always valid. The only downside is that
     * a stack overflow crash can't be caught, but that's not our failure mode.
     *
     * CRITICAL: Use the RAW rt_sigaction syscall (13), NOT glibc's sigaction().
     * The shim overrides sigaction() and may interfere. Using the raw syscall
     * goes directly to the kernel. */
    {
        struct k_sigaction {
            void (*handler)(int, siginfo_t *, void *);
            unsigned long flags;
            void (*restorer)(void);
            unsigned long mask[16];
        };

        /* Local signal restorer function — calls rt_sigreturn syscall.
         * Must be a naked function so the kernel's signal frame layout
         * matches what rt_sigreturn expects. */
        __attribute__((naked))
        void local_restore_rt(void) {
            __asm__ volatile(
                "mov $15, %%rax\n\t"    /* SYS_rt_sigreturn = 15 */
                "syscall\n\t"
                :::
            );
        }

        struct k_sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.handler = crash_handler;
        /* SA_SIGINFO=4 | SA_NODEFER=0x40000000 | SA_RESTORER=0x01000000 */
        extern uint64_t g_tls_g_addr;
        if (g_tls_g_addr) {
            sa.flags = 0x49000004;  /* +SA_ONSTACK=0x08000000 for Go */
        } else {
            sa.flags = 0x41000004;  /* no SA_ONSTACK for non-Go */
        }
        sa.restorer = local_restore_rt;
        memset(sa.mask, 0, sizeof(sa.mask));
        /* Raw rt_sigaction syscall: syscall(13, signum, act, oldact, sigsetsize) */
        long r1 = syscall(13, 11, &sa, NULL, 8);  /* SIGSEGV */
        long r2 = syscall(13, 6,  &sa, NULL, 8);  /* SIGABRT */
        long r3 = syscall(13, 7,  &sa, NULL, 8);  /* SIGBUS */
        long r4 = syscall(13, 8,  &sa, NULL, 8);  /* SIGFPE */

        /* Unblock SIGSEGV and SIGABRT via raw rt_sigprocmask syscall */
        unsigned long unblock_mask[16];
        memset(unblock_mask, 0, sizeof(unblock_mask));
        /* Signal N is bit (N-1) in the sigset. SIGSEGV=11 → bit 10, SIGABRT=6 → bit 5 */
        unblock_mask[0] = (1UL << 10) | (1UL << 5);
        /* rt_sigprocmask: syscall(14, how, set, oldset, sigsetsize)
         * how=1 = SIG_UNBLOCK */
        long r5 = syscall(14, 1, unblock_mask, NULL, 8);

        if (getenv("MACIFY_VERIFY_HANDLER")) {
            char b[256];
            int n = snprintf(b, sizeof(b),
                "macify: raw sigaction: SEGV=%ld ABRT=%ld BUS=%ld FPE=%ld unblock=%ld\n",
                r1, r2, r3, r4, r5);
            (void)write(2, b, n);
        }

        /* Verify handler installation */
        if (getenv("MACIFY_VERIFY_HANDLER")) {
            struct sigaction check;
            memset(&check, 0, sizeof(check));
            sigaction(11, NULL, &check);
            char b[256];
            int n = snprintf(b, sizeof(b),
                "macify: post-install SIGSEGV handler=%p flags=0x%x SA_NODEFER=%d SA_ONSTACK=%d\n",
                (void*)check.sa_sigaction, check.sa_flags,
                (check.sa_flags & SA_NODEFER) ? 1 : 0,
                (check.sa_flags & SA_ONSTACK) ? 1 : 0);
            (void)write(2, b, n);

            /* Check if SIGSEGV is blocked */
            sigset_t curmask;
            sigemptyset(&curmask);
            sigprocmask(0, NULL, &curmask);
            int segv_blocked = sigismember(&curmask, 11);
            n = snprintf(b, sizeof(b),
                "macify: SIGSEGV blocked=%d\n", segv_blocked);
            (void)write(2, b, n);
        }
    }

    /* The asm block switches to the macOS binary's stack, calls main(),
     * then returns here. We flush stdio buffers before exiting because
     * macOS binaries use printf/fwrite which buffer output internally. */
    int ret;
    __asm__ volatile (
        "mov %[entry], %%r11\n\t"          /* save entry in r11 */
        "mov %[stk], %%rsp\n\t"            /* switch to new stack */
        "xor %%rbp, %%rbp\n\t"             /* clear frame pointer */
        /* Load argc from [rsp] into rdi */
        "mov (%%rsp), %%rdi\n\t"
        /* argv = rsp + 8 */
        "lea 8(%%rsp), %%rsi\n\t"
        /* envp = rsp + 8 + (argc+1)*8 */
        "mov %%rdi, %%rax\n\t"
        "inc %%rax\n\t"
        "shl $3, %%rax\n\t"
        "lea 8(%%rsp,%%rax), %%rdx\n\t"
        /* apple = after envp NULL */
        "mov %%rdx, %%rcx\n\t"
        "1: add $8, %%rcx\n\t"
        "cmpq $0, -8(%%rcx)\n\t"
        "jne 1b\n\t"
        /* Call main(argc, argv, envp, apple) */
        "call *%%r11\n\t"
        /* main() returned; save return value */
        "mov %%eax, %[ret]\n\t"
        : [ret] "=r"(ret)
        : [entry] "r"(entry), [stk] "r"(stack_top)
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory"
    );
    /* Flush stdio buffers before exiting — macOS binaries use buffered I/O */
    fflush(NULL);
    __asm__ volatile (
        "mov %[code], %%edi\n\t"
        "mov $231, %%eax\n\t"             /* SYS_exit_group */
        "syscall\n\t"
        :
        : [code] "r"(ret)
        : "rax", "rdi"
    );
    __builtin_unreachable();
}



