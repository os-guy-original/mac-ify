#include "macify.h"
#include <sys/utsname.h>


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
    uint64_t *argv_ptrs = calloc((size_t)argc, sizeof(uint64_t));
    uint64_t *envp_ptrs = calloc((size_t)nenv + 1, sizeof(uint64_t));

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

    for (int i = 0; i < 0x400 - sizeof(gs_test_pattern) - 7; i++) {
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

        /* Check kernel version: only use wrgsbase on 5.15+ */
        static int use_wrgsbase = -1;
        if (use_wrgsbase == -1) {
            struct utsname uts;
            if (uname(&uts) == 0) {
                int major = 0, minor = 0;
                sscanf(uts.release, "%d.%d", &major, &minor);
                /* FSGSBASE signal handling was fixed in 5.15 */
                if (major > 5 || (major == 5 && minor >= 15)) {
                    /* Also check CPU supports FSGSBASE */
                    unsigned int eax, ebx, ecx, edx;
                    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                                     : "0"(7), "2"(0));
                    use_wrgsbase = (ebx & (1 << 16)) ? 1 : 0;
                } else {
                    use_wrgsbase = 0;  /* Old kernel, don't use wrgsbase */
                }
            } else {
                use_wrgsbase = 0;
            }
        }

        if (use_wrgsbase) {
            __asm__ volatile("wrgsbase %0" :: "r"(gs_base));
            /* Also call arch_prctl to sync the shadow */
            syscall(158, 0x1001, gs_base);  /* ARCH_SET_GS */
        } else {
            /* Old kernel: use only arch_prctl (reliable but slower) */
            long prctl_ret = syscall(158, 0x1001, gs_base);  /* ARCH_SET_GS */
            if (g_verbose) {
                fprintf(stderr, "macify: arch_prctl(ARCH_SET_GS) returned %ld\n", prctl_ret);
            }
        }
        if (g_verbose) {
            /* Verify GS base was set correctly */
            uint64_t verify = 0;
            syscall(158, 0x1004, (uint64_t)&verify);  /* ARCH_GET_GS */
            fprintf(stderr, "macify: setup_gs_base: tls_g=0x%lx gs_base=0x%lx (wrgsbase=%d) verify=0x%lx %s\n",
                    (unsigned long)tls_g_addr, (unsigned long)gs_base, use_wrgsbase,
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

    /* For Go binaries: block SIGURG (async preemption signal) before
     * calling entry point. SIGURG is Go's preemption signal — if it
     * arrives before m.gsignal is allocated, the signal handler crashes.
     *
     * We only block SIGURG (not all signals) because Go's schedinit
     * saves/restores the signal mask, and blocking everything would
     * prevent Go's timer-based preemption (SIGVTALRM) from working. */
    if (g_tls_g_addr) {
        sigset_t go_mask;
        sigemptyset(&go_mask);
        sigaddset(&go_mask, 23);  /* SIGURG (Linux) = macOS SIGURG (16) */
        sigprocmask(SIG_BLOCK, &go_mask, NULL);
        if (g_verbose) {
            fprintf(stderr, "macify: Go binary — blocking SIGURG until runtime initializes\n");
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
        : "rax", "rcx", "rdx", "rsi", "rdi", "r11", "memory"
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



