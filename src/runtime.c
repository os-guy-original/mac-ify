#include "macify.h"


/* Stack setup — build the macOS-style entry stack:
 *   [argc] [argv[0..argc-1]] [NULL] [envp[0..n-1]] [NULL] [apple[0]] [NULL]
 */

uint64_t setup_stack(int argc, char **argv, char **envp, void **out_stack_base, size_t *out_stack_size) {
    const size_t stack_size = 8 * 1024 * 1024;
    void *stack = mmap(NULL, stack_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

__attribute__((noreturn))
void call_main_and_exit(uint64_t entry, uint64_t stack_top) {
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



