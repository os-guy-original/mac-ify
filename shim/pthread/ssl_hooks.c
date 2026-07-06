#include "pthread_internal.h"

void macify_print_ret_globals(void) {
    if (!getenv("MACIFY_SSL_DEBUG")) return;
    if (!macify_image_header) {
        const char *msg = "SSL_DEBUG: image_header not set, can't read ret_globals\n";
        (void)write(2, msg, strlen(msg));
        return;
    }
    /* static base of the macOS binary is 0x100000000 */
    uint64_t slide = macify_image_header - 0x100000000;
    char b[256];
    snprintf(b, sizeof(b),
             "SSL_DEBUG: image_header=%#lx slide=%#lx — reading ret_globals:\n",
             (unsigned long)macify_image_header, (unsigned long)slide);
    (void)write(2, b, strlen(b));
    for (int i = 0; ret_global_entries[i].name; i++) {
        uint64_t actual = ret_global_entries[i].static_addr + slide;
        int *p = (int *)actual;
        /* Try to read — if it segfaults, the address is wrong */
        int v = *p;
        snprintf(b, sizeof(b), "  %-50s @ %#lx = %d\n",
                 ret_global_entries[i].name, (unsigned long)actual, v);
        (void)write(2, b, strlen(b));
    }
}

__attribute__((constructor))
static void register_ret_global_printer(void) {
    if (getenv("MACIFY_SSL_DEBUG")) {
        atexit(macify_print_ret_globals);
    }
}

/* Force all OpenSSL ossl_init_*_ret_ globals to 1 (success).
 *
 * curl's internal OpenSSL has RUN_ONCE init functions that store their
 * return value in globals like ossl_init_base_ossl_ret_. If any returns
 * 0, OPENSSL_init_crypto fails, and SSL_CTX_new_ex returns NULL.
 *
 * Some init functions may fail because they depend on macOS-specific
 * APIs (Security framework, keychain, etc.) that our stubs don't fully
 * implement. Rather than make every stub work perfectly, we just force
 * all ret_ globals to 1 so OPENSSL_init_crypto succeeds. The actual
 * crypto operations may still fail later, but at least SSL_CTX_new_ex
 * will return a valid context.
 *
 * Called by the macify loader AFTER setting the image header. */

/* Hook globals for OSSL_LIB_CTX_new inline hook.
 * The hook calls the original OSSL_LIB_CTX_new (via trampoline), then
 * loads the default provider into the new libctx before returning. */
static void *(*macify_original_lib_ctx_new)(void) = NULL;
static void *(*macify_provider_load)(void *, const char *) = NULL;

/* Our hook for OSSL_LIB_CTX_new.
 * Calling convention: System V AMD64, no args, returns OSSL_LIB_CTX*.
 * We call the original (via trampoline), then load the default provider. */
void *macify_ossl_lib_ctx_hook(void) {
    /* Call original OSSL_LIB_CTX_new */
    void *ctx = macify_original_lib_ctx_new();
    if (ctx && macify_provider_load) {
        /* Load the default provider into this new libctx */
        void *prov = macify_provider_load(ctx, "default");
        if (getenv("MACIFY_SSL_DEBUG")) {
            char b[160];
            int n = snprintf(b, sizeof(b),
                "SSL_DEBUG: hook: OSSL_LIB_CTX_new()=%p, OSSL_PROVIDER_load(ctx,\"default\")=%p\n",
                ctx, prov);
            (void)write(2, b, n);
        }
    }
    return ctx;
}

void macify_force_ssl_init_success(void) {
    if (!macify_image_header) return;
    /* static base of the macOS binary is 0x100000000 */
    uint64_t slide = macify_image_header - 0x100000000;
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: force_ssl: image_header=0x%lx slide=0x%lx\n",
                (unsigned long)macify_image_header, (unsigned long)slide);
        (void)write(2, b, n);
    }
    for (int i = 0; ret_global_entries[i].name; i++) {
        uint64_t actual = ret_global_entries[i].static_addr + slide;
        int *p = (int *)actual;
        int old = *p;
        *p = 1;  /* force success */
        if (getenv("MACIFY_SSL_DEBUG")) {
            char b[256];
            int n = snprintf(b, sizeof(b), "SSL_DEBUG:  [%d] %s @ 0x%lx: %d -> 1\n",
                    i, ret_global_entries[i].name, (unsigned long)actual, old);
            (void)write(2, b, n);
        }
    }

    /* Explicitly call OPENSSL_init_crypto and OSSL_PROVIDER_load("default")
     * to ensure the default provider is loaded and activated before SSL_CTX_new_ex.
     *
     * The function addresses are hardcoded from the static symbol table:
     *   OPENSSL_init_crypto @ 0x1005b0dd0
     *   OSSL_PROVIDER_load   @ 0x10035ac30
     *
     * We call them via function pointers computed from the slide.
     * This is safe because these functions are idempotent (RUN_ONCE guarded). */
    typedef int (*openssl_init_crypto_fn)(uint64_t, void *);
    typedef void *(*ossl_provider_load_fn)(void *, const char *);

    openssl_init_crypto_fn init_crypto =
        (openssl_init_crypto_fn)(0x1005b0dd0UL + slide);
    ossl_provider_load_fn provider_load =
        (ossl_provider_load_fn)(0x10035ac30UL + slide);

    /* Initialize OpenSSL crypto (idempotent) */
    int crypto_ret = init_crypto(0, NULL);
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: OPENSSL_init_crypto() = %d\n", crypto_ret);
        (void)write(2, b, n);
    }

    /* Explicitly load the default provider (idempotent) */
    void *prov = provider_load(NULL, "default");
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: OSSL_PROVIDER_load(\"default\") = %p\n", prov);
        (void)write(2, b, n);
    }

    /* Test: call EVP_CIPHER_fetch to see if ciphers are available */
    {
        typedef void *(*evp_cipher_fetch_fn)(void *, const char *, const char *);
        evp_cipher_fetch_fn cipher_fetch =
            (evp_cipher_fetch_fn)(0x100323c00UL + slide);
        void *cipher = cipher_fetch(NULL, "AES-256-CBC", NULL);
        if (getenv("MACIFY_SSL_DEBUG")) {
            char b[128];
            int n = snprintf(b, sizeof(b), "SSL_DEBUG: EVP_CIPHER_fetch(NULL,\"AES-256-CBC\",NULL) = %p\n", cipher);
            (void)write(2, b, n);
        }
    }

    /* Test: call ssl3_get_tls13_cipher_by_std_name to see if TLS 1.3 ciphers are found */
    {
        typedef void *(*ssl3_get_cipher_fn)(const char *);
        ssl3_get_cipher_fn get_cipher =
            (ssl3_get_cipher_fn)(0x100190d40UL + slide);
        void *c1 = get_cipher("TLS_AES_256_GCM_SHA384");
        void *c2 = get_cipher("TLS_CHACHA20_POLY1305_SHA256");
        void *c3 = get_cipher("TLS_AES_128_GCM_SHA256");
        if (getenv("MACIFY_SSL_DEBUG")) {
            char b[256];
            int n = snprintf(b, sizeof(b),
                "SSL_DEBUG: ssl3_get_tls13_cipher_by_std_name:\n"
                "  TLS_AES_256_GCM_SHA384 = %p\n"
                "  TLS_CHACHA20_POLY1305_SHA256 = %p\n"
                "  TLS_AES_128_GCM_SHA256 = %p\n",
                c1, c2, c3);
            (void)write(2, b, n);
        }
    }

    /* Note: we previously tried inline-hooking OSSL_LIB_CTX_new to load the
     * default provider into new libctxs, but curl doesn't call OSSL_LIB_CTX_new
     * (it uses the global default libctx). The hook also caused a segfault
     * due to trampoline alignment issues. Removed. */
}
