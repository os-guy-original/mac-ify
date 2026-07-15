#include "pthread_internal.h"

int   (*real_mutex_lock)(pthread_mutex_t *);
int   (*real_mutex_trylock)(pthread_mutex_t *);
int   (*real_mutex_unlock)(pthread_mutex_t *);
int   (*real_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
int   (*real_mutex_destroy)(pthread_mutex_t *);
int   (*real_cond_wait)(pthread_cond_t *, pthread_mutex_t *);
int   (*real_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
int   (*real_cond_signal)(pthread_cond_t *);
int   (*real_cond_broadcast)(pthread_cond_t *);
int   (*real_cond_init)(pthread_cond_t *, const pthread_condattr_t *);
int   (*real_cond_destroy)(pthread_cond_t *);
int   (*real_rwlock_rdlock)(pthread_rwlock_t *);
int   (*real_rwlock_wrlock)(pthread_rwlock_t *);
int   (*real_rwlock_unlock)(pthread_rwlock_t *);
int   (*real_rwlock_init)(pthread_rwlock_t *, const pthread_rwlockattr_t *);
int   (*real_rwlock_destroy)(pthread_rwlock_t *);

void init_real_pthread_funcs(void) {
    real_mutex_lock     = macify_elf_lookup("pthread_mutex_lock");
    real_mutex_trylock  = macify_elf_lookup("pthread_mutex_trylock");
    real_mutex_unlock   = macify_elf_lookup("pthread_mutex_unlock");
    real_mutex_init     = macify_elf_lookup("pthread_mutex_init");
    real_mutex_destroy  = macify_elf_lookup("pthread_mutex_destroy");
    real_cond_wait      = macify_elf_lookup("pthread_cond_wait");
    real_cond_timedwait = macify_elf_lookup("pthread_cond_timedwait");
    real_cond_signal    = macify_elf_lookup("pthread_cond_signal");
    real_cond_broadcast = macify_elf_lookup("pthread_cond_broadcast");
    real_cond_init      = macify_elf_lookup("pthread_cond_init");
    real_cond_destroy   = macify_elf_lookup("pthread_cond_destroy");
    real_rwlock_rdlock  = macify_elf_lookup("pthread_rwlock_rdlock");
    real_rwlock_wrlock  = macify_elf_lookup("pthread_rwlock_wrlock");
    real_rwlock_unlock  = macify_elf_lookup("pthread_rwlock_unlock");
    real_rwlock_init    = macify_elf_lookup("pthread_rwlock_init");
    real_rwlock_destroy = macify_elf_lookup("pthread_rwlock_destroy");
}

/* Convert a macOS-format mutex to glibc format in-place. The macOS mutex
 * is larger than glibc's (64+ vs 40 bytes), so overwriting the first
 * sizeof(pthread_mutex_t) bytes is safe. */
void convert_macos_mutex(pthread_mutex_t *m) {
    unsigned int sig = *(unsigned int *)m;
    if (sig == MACOS_PTHREAD_MUTEX_SIG) {
        static const pthread_mutex_t glibc_init = PTHREAD_MUTEX_INITIALIZER;
        memcpy(m, &glibc_init, sizeof(pthread_mutex_t));
    }
}

void convert_macos_cond(pthread_cond_t *c) {
    unsigned int sig = *(unsigned int *)c;
    if (sig == MACOS_PTHREAD_COND_SIG) {
        /* macOS pthread_cond_t is 64 bytes (8-byte long __sig + 56-byte opaque).
         * glibc's pthread_cond_t is 48 bytes. Since macOS cond is LARGER,
         * we can safely write glibc's PTHREAD_COND_INITIALIZER directly
         * into the macOS cond buffer (in-place conversion).
         *
         * This is MUCH safer than the old heap-allocation + magic-signature
         * scheme. The old scheme stored "MCCN" (0x4D43434E) at offset 0,
         * which glibc's internal code misinterpreted as a pointer, causing
         * SIGSEGV at [0x4D43434E + offset]. */
        static const pthread_cond_t glibc_init = PTHREAD_COND_INITIALIZER;
        memcpy(c, &glibc_init, sizeof(pthread_cond_t));
    }
}

/* After convert_macos_cond, the cond IS a glibc cond — just return it. */
pthread_cond_t *get_glibc_cond(pthread_cond_t *c) {
    return c;
}

void convert_macos_rwlock(pthread_rwlock_t *rw) {
    unsigned int sig = *(unsigned int *)rw;
    if (sig == MACOS_PTHREAD_RWLOCK_SIG) {
        static const pthread_rwlock_t glibc_init = PTHREAD_RWLOCK_INITIALIZER;
        memcpy(rw, &glibc_init, sizeof(pthread_rwlock_t));
    }
}

#define LAZY_INIT() do { \
    if (!real_mutex_lock) init_real_pthread_funcs(); \
} while (0)

int pthread_mutex_lock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    if (getenv("MACIFY_TRACE_MUTEX")) {
        char b[128]; int n = snprintf(b, sizeof(b), "macify: pthread_mutex_lock(%p) sig=0x%x\n", m, *(unsigned*)m);
        (void)write(2, b, n);
    }
    int r = real_mutex_lock(m);
    if (getenv("MACIFY_TRACE_MUTEX")) {
        char b[128]; int n = snprintf(b, sizeof(b), "macify: pthread_mutex_lock(%p) -> %d\n", m, r);
        (void)write(2, b, n);
    }
    return r;
}

int pthread_mutex_trylock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    return real_mutex_trylock(m);
}

int pthread_mutex_unlock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    if (getenv("MACIFY_TRACE_MUTEX")) {
        char b[128]; int n = snprintf(b, sizeof(b), "macify: pthread_mutex_unlock(%p) sig=0x%x\n", m, *(unsigned*)m);
        (void)write(2, b, n);
    }
    return real_mutex_unlock(m);
}

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    LAZY_INIT();
    int r = real_mutex_init(m, a);
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        snprintf(b, sizeof(b),
                 "SSL_DEBUG: pthread_mutex_init mutex=%p attr=%p -> %d\n",
                 (void *)m, (void *)a, r);
        (void)write(2, b, strlen(b));
    }
    return r;
}

int pthread_mutex_destroy(pthread_mutex_t *m) {
    LAZY_INIT();
    /* Only destroy if it's a glibc-format mutex (don't touch macOS sig). */
    unsigned int sig = *(unsigned int *)m;
    if (sig != MACOS_PTHREAD_MUTEX_SIG) return real_mutex_destroy(m);
    return 0;
}

int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_cond(c);
    convert_macos_mutex(m);
    return real_cond_wait(get_glibc_cond(c), m);
}

int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *ts) {
    LAZY_INIT();
    convert_macos_cond(c);
    convert_macos_mutex(m);
    return real_cond_timedwait(get_glibc_cond(c), m, ts);
}

int pthread_cond_signal(pthread_cond_t *c) {
    LAZY_INIT();
    convert_macos_cond(c);
    return real_cond_signal(get_glibc_cond(c));
}

int pthread_cond_broadcast(pthread_cond_t *c) {
    LAZY_INIT();
    convert_macos_cond(c);
    return real_cond_broadcast(get_glibc_cond(c));
}

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    LAZY_INIT();
    /* macOS cond is 64 bytes, glibc's is 48 — init directly in-place */
    return real_cond_init(c, a);
}

int pthread_cond_destroy(pthread_cond_t *c) {
    LAZY_INIT();
    unsigned int sig = *(unsigned int *)c;
    if (sig == MACOS_PTHREAD_COND_SIG) return 0;  /* uninit macOS cond */
    return real_cond_destroy(c);
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rw) {
    LAZY_INIT();
    convert_macos_rwlock(rw);
    return real_rwlock_rdlock(rw);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rw) {
    LAZY_INIT();
    convert_macos_rwlock(rw);
    return real_rwlock_wrlock(rw);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rw) {
    LAZY_INIT();
    convert_macos_rwlock(rw);
    return real_rwlock_unlock(rw);
}

int pthread_rwlock_init(pthread_rwlock_t *rw, const pthread_rwlockattr_t *a) {
    LAZY_INIT();
    int r = real_rwlock_init(rw, a);
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        snprintf(b, sizeof(b),
                 "SSL_DEBUG: pthread_rwlock_init rw=%p attr=%p -> %d\n",
                 (void *)rw, (void *)a, r);
        (void)write(2, b, strlen(b));
    }
    return r;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rw) {
    LAZY_INIT();
    unsigned int sig = *(unsigned int *)rw;
    if (sig != MACOS_PTHREAD_RWLOCK_SIG) return real_rwlock_destroy(rw);
    return 0;
}

