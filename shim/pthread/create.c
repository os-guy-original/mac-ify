#include "pthread_internal.h"

/* Thread start wrapper: sets up sigaltstack then calls the real routine. */
struct thread_start_args {
    void *(*start_routine)(void *);
    void *arg;
};

static void *thread_start_wrapper(void *p) {
    struct thread_start_args *args = (struct thread_start_args *)p;
    void *(*routine)(void *) = args->start_routine;
    void *arg = args->arg;
    free(p);

    /* Set up a signal stack for this thread (for SA_ONSTACK signal delivery).
     * Without this, SIGSEGV/SIGBUS on this thread kills the process.
     *
     * CRITICAL: Use the RAW sigaltstack syscall (131), NOT the sigaltstack()
     * function. Our shim's sigaltstack() override translates macOS stack_t
     * layout to Linux layout, but we're passing a Linux-format stack_t here
     * (since this code is compiled as Linux code). Calling the override would
     * read the wrong fields (ss_size and ss_flags are at different offsets),
     * resulting in a signal stack with size=0 — which causes signal delivery
     * to fail with SIGSEGV (SI_KERNEL). */
    char *thread_sigstack = mmap(NULL, 256 * 1024, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (thread_sigstack != MAP_FAILED) {
        stack_t ss;
        ss.ss_sp = thread_sigstack;
        ss.ss_size = 256 * 1024;
        ss.ss_flags = 0;
        /* Use raw syscall to bypass our own sigaltstack override */
        syscall(131, &ss, NULL);  /* 131 = SYS_sigaltstack */
    }

    /* For Go binaries: set up a PER-THREAD TLS area for the g pointer.
     *
     * Go's runtime stores the current g pointer at gs:0x30 (TLS). On macOS,
     * the OS provides per-thread TLS via gs:0x30. On Linux, our setup_gs_base
     * sets GS base so that gs:0x30 returns &tls_g (a global).
     *
     * The problem: tls_g is a GLOBAL. When a new thread's crosscall1 writes
     * the new g pointer to gs:0x30, it OVERWRITES the global, which also
     * affects the main thread. This causes race conditions on m0.locks.
     *
     * Fix: allocate a per-thread TLS area (just 8 bytes for the g pointer).
     * Set the new thread's GS base so that gs:0x30 points to this per-thread
     * area. Now crosscall1 writes the new g pointer to the per-thread area,
     * not the global. The main thread's gs:0x30 still returns the global,
     * which has the main thread's g0. */
    extern uint64_t g_tls_g_addr;
    if (g_tls_g_addr) {
        /* Allocate a per-thread 0x100-byte TLS area. Go accesses gs:0x30 to
         * read/write the current g pointer. We put the per-thread g pointer
         * slot at offset 0x30 within this area (so gs_base = area, gs:0x30 = area[0x30]).
         * Other gs: offsets within 0..0xff are also valid (zeroed). */
        char *tls_area = mmap(NULL, 0x100, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (tls_area != MAP_FAILED) {
            /* Zero the area */
            memset(tls_area, 0, 0x100);
            /* Set GS base = tls_area. Then gs:0x30 = *(tls_area + 0x30) = 0 (initially).
             * Go's crosscall1 will write the new g pointer to gs:0x30 (= tls_area+0x30). */
            uint64_t gs_base = (uint64_t)(uintptr_t)tls_area;
            /* Use ONLY arch_prctl (not wrgsbase) — wrgsbase causes crashes on kernel 5.10 */
            syscall(158, 0x1001, gs_base);  /* ARCH_SET_GS */
            if (getenv("MACIFY_TRACE_PTHREAD")) {
                /* Verify GS base was set */
                uint64_t verify = 0;
                syscall(158, 0x1004, (uint64_t)&verify);  /* ARCH_GET_GS */
                uint64_t gs_val = 0;
                __asm__ volatile("movq %%gs:0x30, %0" : "=r"(gs_val));
                char b[256];
                int n = snprintf(b, sizeof(b),
                    "macify: thread_start_wrapper: set gs_base=0x%lx tls_area=%p arch_verify=0x%lx gs:0x30=0x%lx (expected 0)\n",
                    (unsigned long)gs_base, tls_area, (unsigned long)verify, (unsigned long)gs_val);
                (void)write(2, b, n);
            }
        }
    }

    /* Block SIGURG on the new thread to prevent async preemption
     * signals from arriving before Go's runtime is ready.
     * CRITICAL: Use raw syscall, NOT sigprocmask override (which expects
     * macOS sigset format). Also use memset (not sigemptyset) because our
     * sigemptyset override writes only 4 bytes. */
    if (g_tls_g_addr) {
        sigset_t mask;
        memset(&mask, 0, sizeof(mask));
        unsigned long *bits = (unsigned long *)&mask;
        bits[22 / (sizeof(unsigned long) * 8)] |= (1UL << (22 % (sizeof(unsigned long) * 8)));
        syscall(14, 0 /*SIG_BLOCK*/, &mask, NULL, sizeof(mask));
    }

    return routine(arg);
}

int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                   void *(*)(void *), void *);

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    if (!real_pthread_create) {
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    }
    if (getenv("MACIFY_TRACE_PTHREAD") || getenv("MACIFY_NET_DEBUG")) {
        char b[128];
        snprintf(b, sizeof(b), "macify: pthread_create(start_routine=%p arg=%p attr=%p)\n",
                 (void *)start_routine, arg, attr);
        (void)write(2, b, strlen(b));
    }
    pthread_attr_t *glibc_attr = NULL;
    if (attr) {
        struct macos_pthread_attr *ma = (struct macos_pthread_attr *)(uintptr_t)attr;
        if (ma->sig == MACOS_PTHREAD_ATTR_SIG) {
            glibc_attr = (pthread_attr_t *)ma->opaque;
        } else {
            glibc_attr = (pthread_attr_t *)(uintptr_t)attr;
        }
    }
    /* Wrap start_routine to set up sigaltstack for the new thread. */
    struct thread_start_args *wrapper_args = malloc(sizeof(*wrapper_args));
    if (!wrapper_args) return EAGAIN;
    wrapper_args->start_routine = start_routine;
    wrapper_args->arg = arg;
    int ret = real_pthread_create(thread, glibc_attr, thread_start_wrapper, wrapper_args);
    if (ret != 0) {
        free(wrapper_args);
    }
    return ret;
}

/* ============================================================================
 * SSL init ret_global reader — for debugging OPENSSL_init_crypto failures.
 *
 * Each OpenSSL RUN_ONCE init function (ossl_init_X_ossl_) stores its return
 * value in a global variable (ossl_init_X_ossl_ret_). If any returns 0,
 * OPENSSL_init_crypto fails, which causes SSL_CTX_new to fail with
 * "SSL: could not create a context" (SSL reason 20).
 *
 * The shim can read these globals from the loaded macOS binary's memory.
 * The static addresses (from the symbol table) are hardcoded; we subtract
 * the static base (0x100000000) and add the actual image header address
 * (set by the loader via __macify_set_image_header).
 *
 * This is enabled by MACIFY_SSL_DEBUG=1.
 * ========================================================================== */

extern uint64_t macify_image_header;

/* ret_global_entry and ret_global_entries are forward-declared above
 * (before pthread_once) so the pthread_once override can access them. */

const struct ret_global_entry ret_global_entries[] = {
    {"ssl_x509_store_ctx_init_ossl_ret_",               0x1007ab050},
    {"ossl_init_ssl_base_ossl_ret_",                    0x1007ab054},
    {"do_bio_type_init_ossl_ret_",                      0x1007ab06c},
    {"do_load_builtin_modules_ossl_ret_",               0x1007ab0b8},
    {"do_init_module_list_lock_ossl_ret_",              0x1007ab0bc},
    {"do_err_strings_init_ossl_ret_",                   0x1007ab0f0},
    {"default_context_do_thread_key_init_ossl_ret_",    0x1007ab3f8},
    {"default_context_do_init_ossl_ret_",               0x1007ab3fc},
    {"ossl_init_base_ossl_ret_",                        0x1007ab658},
    {"ossl_init_load_crypto_strings_ossl_ret_",         0x1007ab65c},
    {"ossl_init_load_ssl_strings_ossl_ret_",            0x1007ab660},
    {"ossl_init_add_all_ciphers_ossl_ret_",             0x1007ab664},
    {"ossl_init_add_all_digests_ossl_ret_",             0x1007ab668},
    {"ossl_init_config_ossl_ret_",                      0x1007ab66c},
    {"ossl_init_async_ossl_ret_",                       0x1007ab678},
    {"create_global_tevent_register_ossl_ret_",         0x1007ab680},
    {"o_names_init_ossl_ret_",                          0x1007ab718},
    {"obj_api_initialise_ossl_ret_",                    0x1007ab750},
    {"o_sig_init_ossl_ret_",                            0x1007ab770},
    {"do_rand_init_ossl_ret_",                          0x1007ab790},
    {"do_registry_init_ossl_ret_",                      0x1007ab8a0},
    {"ui_method_data_index_init_ossl_ret_",             0x1007abb78},
    {NULL, 0}
};

/* Made non-static so shim_misc.c:exit() can call it directly when
 * MACIFY_SSL_DEBUG is set. The macify loader bypasses atexit handlers
 * (post_main_cleanup calls _exit directly), so an atexit registration
 * alone never fires. */
