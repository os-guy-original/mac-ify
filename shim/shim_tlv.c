#include "shim.h"

void _tlv_atexit(void (*fn)(void *), void *arg) {
    /* Register with atexit — simplified, doesn't perfectly match macOS semantics */
    /* For now, just call the function immediately on exit via atexit */
    (void)fn; (void)arg;
    /* No-op for now — TLV cleanup is not critical for most apps */
}
/* TLV section info, set by the loader */
static void *tlv_data_base = NULL;       /* __thread_data section addr (slid) */
static size_t tlv_data_size = 0;         /* __thread_data section size */
static size_t tlv_bss_size = 0;          /* __thread_bss section size */
/* Total per-thread block = tlv_data_size + tlv_bss_size */

/* Per-thread TLV block */
static pthread_key_t tlv_block_key;
static pthread_once_t tlv_block_once = PTHREAD_ONCE_INIT;

static void tlv_block_destructor(void *arg) {
    free(arg);
}

static void tlv_block_init(void) {
    pthread_key_create(&tlv_block_key, tlv_block_destructor);
}

/* Called by the loader to set TLV section info */
void __macify_set_tlv_info(void *data_base, size_t data_size, size_t bss_size) {
    tlv_data_base = data_base;
    tlv_data_size = data_size;
    tlv_bss_size = bss_size;
}

/* Get or create the per-thread TLV block */
static void *get_tlv_block(void) {
    pthread_once(&tlv_block_once, tlv_block_init);

    void *block = pthread_getspecific(tlv_block_key);
    if (!block) {
        size_t total = tlv_data_size + tlv_bss_size;
        if (total == 0) total = 4096;  /* fallback */
        block = calloc(1, total);
        /* Initialize: copy __thread_data initial values */
        if (tlv_data_base && tlv_data_size > 0) {
            memcpy(block, tlv_data_base, tlv_data_size);
        }
        /* __thread_bss is already zeroed by calloc */
        pthread_setspecific(tlv_block_key, block);
    }
    return block;
}

/* C implementation of TLV bootstrap. Called from the assembly wrapper
 * which preserves caller-saved registers. Returns pointer to the
 * variable's per-thread storage. */
static __thread int tlv_recursion_depth = 0;
void *__tlv_bootstrap_impl(struct tlv_descriptor *desc) {
    if (++tlv_recursion_depth > 10) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf),
            "macify: TLV recursion detected (depth=%d) desc=%p offset=%lu\n",
            tlv_recursion_depth, desc, desc ? desc->offset : 0);
        write(2, buf, n);
        _exit(1);
    }
    void *block = get_tlv_block();
    tlv_recursion_depth--;
    return (char *)block + desc->offset;
}

/* macOS TLV thunk ABI requires preserving ALL registers except rax.
 * Rust's runtime (and possibly other code) relies on this — it loads
 * rcx/rdx/rsi before calling the thunk and uses them after, expecting
 * them to be unchanged. glibc's pthread_getspecific clobbers these,
 * so we wrap the C implementation in an assembly trampoline that
 * saves and restores all caller-saved registers.
 *
 * Stack layout after the 9 pushes (top to bottom):
 *   rsp+0x00: saved r11
 *   rsp+0x08: saved r10
 *   rsp+0x10: saved r9
 *   rsp+0x18: saved r8
 *   rsp+0x20: saved rdi   <- original desc argument
 *   rsp+0x28: saved rsi
 *   rsp+0x30: saved rdx
 *   rsp+0x38: saved rcx
 *   rsp+0x40: saved rax
 * Then the call to __tlv_bootstrap_impl pushes a return address at rsp-8.
 *
 * We pass desc (saved at rsp+0x20) as rdi to the C function.
 * After the call, we overwrite the saved rax slot with the return value,
 * then pop all 9 registers. The final pop rax restores the (now overwritten)
 * saved value, which is the return value.
 */
__attribute__((naked))
void *tlv_bootstrap(struct tlv_descriptor *desc) {
    __asm__ volatile (
        "push %rax\n\t"
        "push %rcx\n\t"
        "push %rdx\n\t"
        "push %rsi\n\t"
        "push %rdi\n\t"
        "push %r8\n\t"
        "push %r9\n\t"
        "push %r10\n\t"
        "push %r11\n\t"
        "movq 0x20(%rsp), %rdi\n\t"     /* rdi = original desc (saved at rsp+0x20) */
        "call __tlv_bootstrap_impl\n\t"
        "movq %rax, 0x40(%rsp)\n\t"     /* overwrite saved rax with return value */
        "pop %r11\n\t"
        "pop %r10\n\t"
        "pop %r9\n\t"
        "pop %r8\n\t"
        "pop %rdi\n\t"
        "pop %rsi\n\t"
        "pop %rdx\n\t"
        "pop %rcx\n\t"
        "pop %rax\n\t"                  /* restores return value (was overwritten) */
        "ret\n\t"
    );
}

/* _tlv_bootstrap and tlv_get_addr are aliases for tlv_bootstrap — they
 * all use the same assembly wrapper that preserves registers. */
void *_tlv_bootstrap(struct tlv_descriptor *desc) {
    return tlv_bootstrap(desc);
}

void *tlv_get_addr(struct tlv_descriptor *desc) {
    return tlv_bootstrap(desc);
}
