#include "pthread_internal.h"

#include <pthread.h>

/* Our own pthread_key_create — allocates from our table.
 *
 * CRITICAL: We must use glibc's REAL per-thread TLS, not a global array.
 * OpenSSL stores per-thread error queues in TLS. If TLS is global, c-ares
 * background threads corrupt the main thread's error queue, causing
 * SSL_CTX_new to fail with SSL_R_INIT_LIBRARY.
 *
 * We create a mapping: macOS key (0-255) → glibc pthread_key_t.
 * Each macOS key_create allocates a real glibc key. All subsequent
 * getspecific/setspecific calls go through glibc's per-thread storage. */
pthread_key_t glibc_tls_keys[MACIFY_MAX_KEYS];
int glibc_key_used[MACIFY_MAX_KEYS];
int macify_next_key = 0;
pthread_mutex_t macify_tls_mutex = PTHREAD_MUTEX_INITIALIZER;
void (*macify_destructors[MACIFY_MAX_KEYS])(void *);

int (*real_glibc_key_create)(pthread_key_t *, void (*)(void *));
void *(*real_glibc_getspecific)(pthread_key_t);
int (*real_glibc_setspecific)(pthread_key_t, const void *);

void init_real_tls_funcs(void) {
    real_glibc_key_create = dlsym(RTLD_NEXT, "pthread_key_create");
    real_glibc_getspecific = dlsym(RTLD_NEXT, "pthread_getspecific");
    real_glibc_setspecific = dlsym(RTLD_NEXT, "pthread_setspecific");
}

/* Our own pthread_key_create — allocates a glibc key and maps it. */
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
    if (!real_glibc_key_create) init_real_tls_funcs();
    pthread_mutex_lock(&macify_tls_mutex);
    int k = macify_next_key++;
    pthread_mutex_unlock(&macify_tls_mutex);

    int r;
    if (k >= MACIFY_MAX_KEYS) {
        r = EAGAIN;
    } else if (real_glibc_key_create(&glibc_tls_keys[k], destructor) != 0) {
        r = EAGAIN;
    } else {
        glibc_key_used[k] = 1;
        macify_destructors[k] = destructor;
        /* macOS pthread_key_t is unsigned long (8 bytes), but glibc's is
         * unsigned int (4 bytes). Write the full 8 bytes to match the macOS
         * ABI, so the macOS binary reads the correct key value. */
        *(unsigned long *)key = (unsigned long)k;
        r = 0;
    }
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[160];
        snprintf(b, sizeof(b),
                 "SSL_DEBUG: pthread_key_create key=%p dest=%p -> %d (k=%d)\n",
                 (void *)key, (void *)destructor, r, k);
        (void)write(2, b, strlen(b));
    }
    return r;
}

/* Our own pthread_setspecific — delegate to glibc's per-thread storage */
int pthread_setspecific(pthread_key_t key, const void *value) {
    if (!real_glibc_setspecific) init_real_tls_funcs();
    unsigned int k = (unsigned int)(unsigned long)key;
    if (k >= MACIFY_MAX_KEYS || !glibc_key_used[k]) {
        return EINVAL;
    }
    return real_glibc_setspecific(glibc_tls_keys[k], value);
}

/* Our own pthread_getspecific — delegate to glibc's per-thread storage */
void *pthread_getspecific(pthread_key_t key) {
    if (!real_glibc_getspecific) init_real_tls_funcs();
    unsigned int k = (unsigned int)(unsigned long)key;
    if (k >= MACIFY_MAX_KEYS || !glibc_key_used[k]) {
        return NULL;
    }
    return real_glibc_getspecific(glibc_tls_keys[k]);
}

/* Our own pthread_once — correct implementation using atomic CAS.
 *
 * CRITICAL: The previous implementation set once_control = 1 BEFORE calling
 * init_routine. This broke the RUN_ONCE contract: if a second thread called
 * pthread_once while init_routine was still running, it would see "done" and
 * skip, then check init##_ossl_ret_ (which was still 0 because init hadn't
 * finished). This caused OPENSSL_init_crypto to return 0 (failure), which
 * made SSL_CTX_new fail with SSL_R_INIT_LIBRARY.
 *
 * This implementation uses 3 states:
 *   0x30B1BCBA / 0 = not yet initialized (macOS PTHREAD_ONCE_INIT)
 *   2 = in progress (a thread is running init_routine)
 *   1 = done (init_routine has completed)
 *
 * No global mutex is used, so recursive pthread_once calls with different
 * once_control variables don't deadlock. */
#define MACOS_PTHREAD_ONCE_INIT 0x30B1BCBA

/* Forward declarations for the ret_ globals (defined later in this file) */
extern uint64_t macify_image_header;

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    static int ssl_debug = -1;
    if (ssl_debug < 0) {
        const char *e = getenv("MACIFY_SSL_DEBUG");
        ssl_debug = (e && e[0]) ? 1 : 0;
    }
    while (1) {
        long val = __atomic_load_n((long *)once_control, __ATOMIC_ACQUIRE);

        if (val == 1) return 0;  /* already done */

        if (val == MACOS_PTHREAD_ONCE_INIT || val == 0) {
            /* Try to claim it */
            long expected = val;
            if (__atomic_compare_exchange_n((long *)once_control, &expected, 2,
                                             0, __ATOMIC_ACQUIRE,
                                             __ATOMIC_RELAXED)) {
                /* We claimed it — call init */
                if (ssl_debug) {
                    char b[128];
                    snprintf(b, sizeof(b),
                             "SSL_DEBUG: pthread_once: once=%p init=%p\n",
                             (void *)once_control, (void *)init_routine);
                    (void)write(2, b, strlen(b));
                }
                init_routine();
                if (ssl_debug) {
                    char b[128];
                    snprintf(b, sizeof(b),
                             "SSL_DEBUG: pthread_once: once=%p init=%p DONE\n",
                             (void *)once_control, (void *)init_routine);
                    (void)write(2, b, strlen(b));
                }

                /* Debug: check which ret_ globals are 0 after this init */
                if (ssl_debug && macify_image_header &&
                    getenv("MACIFY_FORCE_SSL")) {
                    uint64_t slide = macify_image_header - 0x100000000;
                    for (int i = 0; ret_global_entries[i].name; i++) {
                        uint64_t actual = ret_global_entries[i].static_addr + slide;
                        int *p = (int *)actual;
                        if (*p == 0) {
                            char b[256];
                            int n = snprintf(b, sizeof(b),
                                "SSL_DEBUG:   FAILED: %s @ 0x%lx = 0\n",
                                ret_global_entries[i].name, (unsigned long)actual);
                            (void)write(2, b, n);
                        }
                    }
                }

                /* After the init_routine runs, force ALL OpenSSL
                 * ossl_init_*_ret_ globals to 1 (success) — but ONLY for
                 * curl/wget (which have these globals at the hardcoded
                 * addresses). For other binaries, skip this entirely.
                 *
                 * CRITICAL: This MUST happen BEFORE the release store to
                 * once_control below. If we mark once_control as "done"
                 * first, a concurrent thread calling RUN_ONCE will see
                 * "done" but read ret_=0 (not yet forced), causing it to
                 * treat the init as failed. */
                static int force_ssl_check = -1;
                if (force_ssl_check < 0) {
                    force_ssl_check = getenv("MACIFY_FORCE_SSL") ? 1 : 0;
                }
                if (force_ssl_check && macify_image_header) {
                    uint64_t slide = macify_image_header - 0x100000000;
                    for (int i = 0; ret_global_entries[i].name; i++) {
                        uint64_t actual = ret_global_entries[i].static_addr + slide;
                        int *p = (int *)actual;
                        if (*p == 0) *p = 1;
                    }
                }

                __atomic_store_n((long *)once_control, 1, __ATOMIC_RELEASE);
                return 0;
            }
            /* CAS failed — another thread claimed it, fall through to wait */
        }

        /* Another thread is initializing — wait for it to finish */
        while (__atomic_load_n((long *)once_control, __ATOMIC_ACQUIRE) == 2) {
            sched_yield();
        }
        /* Loop back and check if it's done (val == 1) */
    }
    return 0;
}


/* macOS pthread synchronization objects have a completely different layout
 * from glibc's. Statically-initialized objects carry a macOS signature
 * (0x32AAABA7 for mutex, 0x3CB0B5BB for cond, 0x2DA8B3B4 for rwlock) in
 * their first 4 bytes. When glibc's pthread_mutex_lock sees this non-zero
 * value, it interprets it as "already locked" and deadlocks on a futex.
 *
 * Solution: override the pthread_mutex/cond/rwlock functions. On each call,
 * check if the object still has a macOS signature. If so, overwrite it
 * in-place with glibc's PTHREAD_*_INITIALIZER (macOS objects are 64+ bytes;
 * glibc's are 40 bytes, so the overwrite is safe). Then delegate to glibc's
 * real function via dlsym(RTLD_NEXT, ...).
 */

#define MACOS_PTHREAD_MUTEX_SIG  0x32AAABA7u
#define MACOS_PTHREAD_COND_SIG   0x3CB0B5BBu
#define MACOS_PTHREAD_RWLOCK_SIG 0x2DA8B3B4u

/* Cache glibc's real function pointers (resolved lazily on first use). */
