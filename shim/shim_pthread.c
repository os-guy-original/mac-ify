#include "shim.h"
#include <time.h>
#include <sched.h>

/* macOS clock ID constants differ from Linux:
 *   macOS CLOCK_REALTIME=0, CLOCK_MONOTONIC=6, CLOCK_PROCESS_CPUTIME_ID=12,
 *   CLOCK_THREAD_CPUTIME_ID=16
 *   Linux CLOCK_REALTIME=0, CLOCK_MONOTONIC=1, CLOCK_PROCESS_CPUTIME_ID=2,
 *   CLOCK_THREAD_CPUTIME_ID=3
 * OpenSSL and other libraries call clock_gettime with macOS clock IDs.
 * We translate them to Linux equivalents. */
#define MACOS_CLOCK_MONOTONIC             6
#define MACOS_CLOCK_PROCESS_CPUTIME_ID   12
#define MACOS_CLOCK_THREAD_CPUTIME_ID    16
#define MACOS_CLOCK_UPTIME_RAW           8
#define MACOS_CLOCK_MONOTONIC_RAW        4

int macify_clock_gettime(int clk_id, struct timespec *tp) __asm__("clock_gettime");
int macify_clock_gettime(int clk_id, struct timespec *tp) {
    switch (clk_id) {
        case MACOS_CLOCK_MONOTONIC:
            clk_id = CLOCK_MONOTONIC;
            break;
        case MACOS_CLOCK_PROCESS_CPUTIME_ID:
            clk_id = CLOCK_PROCESS_CPUTIME_ID;
            break;
        case MACOS_CLOCK_THREAD_CPUTIME_ID:
            clk_id = CLOCK_THREAD_CPUTIME_ID;
            break;
        case MACOS_CLOCK_UPTIME_RAW:
        case MACOS_CLOCK_MONOTONIC_RAW:
            clk_id = CLOCK_MONOTONIC_RAW;
            break;
        /* CLOCK_REALTIME (0) is the same on both platforms */
    }
    static int (*real_clock_gettime)(int, struct timespec *) = NULL;
    if (!real_clock_gettime) real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    return real_clock_gettime(clk_id, tp);
}

int _pthread_getname_np(pthread_t thread, char *name, size_t len) {
    return pthread_getname_np(thread, name, len);
}

/* OSSpinLock — deprecated macOS spinlock. We implement using atomic ops.
 * OSSpinLock is just an int32_t: 0 = unlocked, 1 = locked. */
void OSSpinLockLock(volatile int32_t *lock) {
    while (__sync_lock_test_and_set(lock, 1)) {
        while (*lock) __asm__ volatile("pause");
    }
}
void OSSpinLockUnlock(volatile int32_t *lock) {
    __sync_lock_release(lock);
}
int OSSpinLockTry(volatile int32_t *lock) {
    return __sync_lock_test_and_set(lock, 1) == 0;
}

/* pthread_atfork — register fork handlers. Pass through to glibc.
 * On glibc 2.34+, pthread_atfork only exists as a versioned symbol
 * with no default version, so dlsym returns NULL. Must use dlvsym. */
int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void)) {
    static int (*real_atfork)(void (*)(void), void (*)(void), void (*)(void)) = NULL;
    if (!real_atfork) {
        real_atfork = dlvsym(RTLD_NEXT, "pthread_atfork", "GLIBC_2.2.5");
        if (!real_atfork) real_atfork = dlsym(RTLD_NEXT, "pthread_atfork");
    }
    return real_atfork(prepare, parent, child);
}

/* pthread_threadid_np — macOS function to get a unique thread ID.
 * Linux doesn't have this; use gettid() syscall instead. */
int pthread_threadid_np(pthread_t thread, uint64_t *thread_id) {
    (void)thread;
    if (thread_id) *thread_id = (uint64_t)syscall(186);  /* SYS_gettid */
    return 0;
}
/* pthread_cond_timedwait_relative_np — macOS-specific variant that takes
 * a RELATIVE timeout (nanoseconds from now) instead of an absolute time.
 * Linux's pthread_cond_timedwait uses absolute time, so we convert. */
int pthread_cond_timedwait_relative_np(pthread_cond_t *c, pthread_mutex_t *m,
                                        const struct timespec *reltime) {
    if (!reltime) return pthread_cond_wait(c, m);
    struct timespec abstime;
    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_sec += reltime->tv_sec;
    abstime.tv_nsec += reltime->tv_nsec;
    if (abstime.tv_nsec >= 1000000000) {
        abstime.tv_sec++;
        abstime.tv_nsec -= 1000000000;
    }
    return pthread_cond_timedwait(c, m, &abstime);
}

/* macOS pthread extensions. */

/* The loader allocates an 8MB stack for the macOS binary and switches to
 * it before calling main(). But glibc's pthread_getattr_np for the main
 * thread still returns the KERNEL's stack info (from /proc/self/maps),
 * not our allocated stack. Rust's runtime uses pthread_get_stackaddr_np
 * to find the main thread's stack, computes guard page addresses from it,
 * and crashes when those don't match the actual stack pointer.
 *
 * Fix: the loader calls __macify_set_stack_info() with our allocated
 * stack base/size. pthread_get_stack*_np returns these values for the
 * main thread instead of querying glibc. */
void *macify_main_stack_base = NULL;
size_t macify_main_stack_size = 0;

void __macify_set_stack_info(void *base, size_t size) {
    macify_main_stack_base = base;
    macify_main_stack_size = size;
}

void *pthread_get_stackaddr_np(pthread_t thread) {
    /* For the main thread, return our allocated stack top. For other
     * threads, query glibc. We detect the main thread by checking if
     * thread == pthread_self() AND our stack info has been set. */
    if (macify_main_stack_base && thread == pthread_self()) {
        return (char *)macify_main_stack_base + macify_main_stack_size;
    }
    pthread_attr_t attr;
    void *stackaddr = NULL;
    size_t stacksize = 0;
    pthread_getattr_np(thread, &attr);
    pthread_attr_getstack(&attr, &stackaddr, &stacksize);
    pthread_attr_destroy(&attr);
    return (char *)stackaddr + stacksize;  /* top of stack */
}

size_t pthread_get_stacksize_np(pthread_t thread) {
    if (macify_main_stack_base && thread == pthread_self()) {
        return macify_main_stack_size;
    }
    pthread_attr_t attr;
    size_t stacksize = 0;
    pthread_getattr_np(thread, &attr);
    pthread_attr_getstacksize(&attr, &stacksize);
    pthread_attr_destroy(&attr);
    return stacksize;
}
/* Self-contained pthread TLS implementation.
 * 
 * macOS and glibc have different pthread_key_t sizes and different
 * pthread_once_t layouts. We bridge them by creating a mapping from
 * macOS key indices (0-255) to real glibc pthread_key_t values.
 * This ensures per-thread storage works correctly — critical for
 * OpenSSL which stores per-thread error queues in TLS.
 */

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
#define MACIFY_MAX_KEYS 256
static pthread_key_t glibc_tls_keys[MACIFY_MAX_KEYS];
static int glibc_key_used[MACIFY_MAX_KEYS];
static int macify_next_key = 0;
static pthread_mutex_t macify_tls_mutex = PTHREAD_MUTEX_INITIALIZER;
static void (*macify_destructors[MACIFY_MAX_KEYS])(void *);

static int (*real_glibc_key_create)(pthread_key_t *, void (*)(void *));
static void *(*real_glibc_getspecific)(pthread_key_t);
static int (*real_glibc_setspecific)(pthread_key_t, const void *);

static void init_real_tls_funcs(void) {
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
        *key = (pthread_key_t)k;
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
static int   (*real_mutex_lock)(pthread_mutex_t *);
static int   (*real_mutex_trylock)(pthread_mutex_t *);
static int   (*real_mutex_unlock)(pthread_mutex_t *);
static int   (*real_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
static int   (*real_mutex_destroy)(pthread_mutex_t *);
static int   (*real_cond_wait)(pthread_cond_t *, pthread_mutex_t *);
static int   (*real_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
static int   (*real_cond_signal)(pthread_cond_t *);
static int   (*real_cond_broadcast)(pthread_cond_t *);
static int   (*real_cond_init)(pthread_cond_t *, const pthread_condattr_t *);
static int   (*real_cond_destroy)(pthread_cond_t *);
static int   (*real_rwlock_rdlock)(pthread_rwlock_t *);
static int   (*real_rwlock_wrlock)(pthread_rwlock_t *);
static int   (*real_rwlock_unlock)(pthread_rwlock_t *);
static int   (*real_rwlock_init)(pthread_rwlock_t *, const pthread_rwlockattr_t *);
static int   (*real_rwlock_destroy)(pthread_rwlock_t *);

static void init_real_pthread_funcs(void) {
    real_mutex_lock     = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    real_mutex_trylock  = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
    real_mutex_unlock   = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    real_mutex_init     = dlsym(RTLD_NEXT, "pthread_mutex_init");
    real_mutex_destroy  = dlsym(RTLD_NEXT, "pthread_mutex_destroy");
    real_cond_wait      = dlsym(RTLD_NEXT, "pthread_cond_wait");
    real_cond_timedwait = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
    real_cond_signal    = dlsym(RTLD_NEXT, "pthread_cond_signal");
    real_cond_broadcast = dlsym(RTLD_NEXT, "pthread_cond_broadcast");
    real_cond_init      = dlsym(RTLD_NEXT, "pthread_cond_init");
    real_cond_destroy   = dlsym(RTLD_NEXT, "pthread_cond_destroy");
    real_rwlock_rdlock  = dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");
    real_rwlock_wrlock  = dlsym(RTLD_NEXT, "pthread_rwlock_wrlock");
    real_rwlock_unlock  = dlsym(RTLD_NEXT, "pthread_rwlock_unlock");
    real_rwlock_init    = dlsym(RTLD_NEXT, "pthread_rwlock_init");
    real_rwlock_destroy = dlsym(RTLD_NEXT, "pthread_rwlock_destroy");
}

/* Convert a macOS-format mutex to glibc format in-place. The macOS mutex
 * is larger than glibc's (64+ vs 40 bytes), so overwriting the first
 * sizeof(pthread_mutex_t) bytes is safe. */
static void convert_macos_mutex(pthread_mutex_t *m) {
    unsigned int sig = *(unsigned int *)m;
    if (sig == MACOS_PTHREAD_MUTEX_SIG) {
        static const pthread_mutex_t glibc_init = PTHREAD_MUTEX_INITIALIZER;
        memcpy(m, &glibc_init, sizeof(pthread_mutex_t));
    }
}

static void convert_macos_cond(pthread_cond_t *c) {
    unsigned int sig = *(unsigned int *)c;
    if (sig == MACOS_PTHREAD_COND_SIG) {
        /* macOS pthread_cond_t is only 32 bytes, but glibc's is 48 bytes.
         * We CANNOT write glibc's PTHREAD_COND_INITIALIZER into the macOS
         * buffer (16-byte overflow). Instead, allocate a glibc cond on the
         * heap and store the pointer in the macOS cond's opaque field. */
        pthread_cond_t *glibc_cond = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
        if (!glibc_cond) return;
        static const pthread_cond_t glibc_init = PTHREAD_COND_INITIALIZER;
        memcpy(glibc_cond, &glibc_init, sizeof(pthread_cond_t));
        /* Store our magic signature and the heap pointer in the macOS cond.
         * macOS cond layout: [sig(4)] [pad(4)] [opaque(24)]
         * We overwrite with: [magic(4)] [pad(4)] [pointer(8)] */
        *(unsigned int *)c = 0x4D43434E;  /* "MCCN" = Macify Cond */
        void **ptr_loc = (void **)((char *)c + 8);
        *ptr_loc = glibc_cond;
    } else if (sig == 0x4D43434E) {
        /* Already converted — heap cond exists */
    }
}

/* Get the glibc cond pointer from a macOS cond (after conversion). */
static pthread_cond_t *get_glibc_cond(pthread_cond_t *c) {
    unsigned int sig = *(unsigned int *)c;
    if (sig == 0x4D43434E) {
        void **ptr_loc = (void **)((char *)c + 8);
        return (pthread_cond_t *)*ptr_loc;
    }
    /* Not converted — it's already a glibc cond (or being used directly) */
    return c;
}

static void convert_macos_rwlock(pthread_rwlock_t *rw) {
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
    return real_mutex_lock(m);
}

int pthread_mutex_trylock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    return real_mutex_trylock(m);
}

int pthread_mutex_unlock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
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
    /* Allocate a glibc cond on the heap (macOS cond is too small for glibc) */
    pthread_cond_t *glibc_cond = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
    if (!glibc_cond) {
        if (getenv("MACIFY_SSL_DEBUG")) {
            char b[128];
            snprintf(b, sizeof(b),
                     "SSL_DEBUG: pthread_cond_init cond=%p attr=%p -> ENOMEM (malloc failed)\n",
                     (void *)c, (void *)a);
            (void)write(2, b, strlen(b));
        }
        return ENOMEM;
    }
    int ret = real_cond_init(glibc_cond, a);
    if (ret != 0) {
        free(glibc_cond);
        if (getenv("MACIFY_SSL_DEBUG")) {
            char b[128];
            snprintf(b, sizeof(b),
                     "SSL_DEBUG: pthread_cond_init cond=%p attr=%p -> %d (real_cond_init failed)\n",
                     (void *)c, (void *)a, ret);
            (void)write(2, b, strlen(b));
        }
        return ret;
    }
    *(unsigned int *)c = 0x4D43434E;  /* Macify Cond magic */
    void **ptr_loc = (void **)((char *)c + 8);
    *ptr_loc = glibc_cond;
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        snprintf(b, sizeof(b),
                 "SSL_DEBUG: pthread_cond_init cond=%p attr=%p -> 0 (glibc_cond=%p)\n",
                 (void *)c, (void *)a, (void *)glibc_cond);
        (void)write(2, b, strlen(b));
    }
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *c) {
    LAZY_INIT();
    unsigned int sig = *(unsigned int *)c;
    if (sig == 0x4D43434E) {
        /* Our heap-allocated cond — destroy and free */
        void **ptr_loc = (void **)((char *)c + 8);
        pthread_cond_t *glibc_cond = (pthread_cond_t *)*ptr_loc;
        int ret = real_cond_destroy(glibc_cond);
        free(glibc_cond);
        return ret;
    }
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


/* macOS pthread_attr_t is only 16 bytes (long sig + pointer), while glibc's
 * is 56 bytes. When glibc's pthread_attr_init writes 56 bytes into a
 * 16-byte macOS-format buffer, it overflows and corrupts the stack. We
 * allocate a glibc-format attr on the heap and store its pointer in the
 * macOS-format attr (which is big enough to hold a pointer + sig). */

static int (*real_attr_init)(pthread_attr_t *);
static int (*real_attr_destroy)(pthread_attr_t *);
static int (*real_attr_setstacksize)(pthread_attr_t *, size_t);
static int (*real_attr_getstacksize)(const pthread_attr_t *, size_t *);
static int (*real_attr_setguardsize)(pthread_attr_t *, size_t);

static void init_real_attr_funcs(void) {
    real_attr_init         = dlsym(RTLD_NEXT, "pthread_attr_init");
    real_attr_destroy      = dlsym(RTLD_NEXT, "pthread_attr_destroy");
    real_attr_setstacksize = dlsym(RTLD_NEXT, "pthread_attr_setstacksize");
    real_attr_getstacksize = dlsym(RTLD_NEXT, "pthread_attr_getstacksize");
    real_attr_setguardsize = dlsym(RTLD_NEXT, "pthread_attr_setguardsize");
}

#define LAZY_INIT_ATTR() do { \
    if (!real_attr_init) init_real_attr_funcs(); \
} while (0)

/* Get the glibc attr from a macOS attr. If the macOS attr doesn't have
 * our signature, allocate a new glibc attr. */
static pthread_attr_t *get_glibc_attr(struct macos_pthread_attr *macos_attr) {
    LAZY_INIT_ATTR();
    if (macos_attr->sig != MACOS_PTHREAD_ATTR_SIG || macos_attr->opaque == NULL) {
        /* Not initialized by us — allocate a new glibc attr */
        pthread_attr_t *glibc_attr = calloc(1, sizeof(pthread_attr_t));
        real_attr_init(glibc_attr);
        macos_attr->sig = MACOS_PTHREAD_ATTR_SIG;
        macos_attr->opaque = glibc_attr;
    }
    return (pthread_attr_t *)macos_attr->opaque;
}

int pthread_attr_init(pthread_attr_t *attr) {
    LAZY_INIT_ATTR();
    struct macos_pthread_attr *ma = (struct macos_pthread_attr *)attr;
    pthread_attr_t *glibc_attr = calloc(1, sizeof(pthread_attr_t));
    real_attr_init(glibc_attr);
    ma->sig = MACOS_PTHREAD_ATTR_SIG;
    ma->opaque = glibc_attr;
    return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr) {
    LAZY_INIT_ATTR();
    struct macos_pthread_attr *ma = (struct macos_pthread_attr *)attr;
    if (ma->sig == MACOS_PTHREAD_ATTR_SIG && ma->opaque) {
        real_attr_destroy((pthread_attr_t *)ma->opaque);
        free(ma->opaque);
        ma->opaque = NULL;
        ma->sig = 0;
    }
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setstacksize(glibc_attr, stacksize);
}

int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)(uintptr_t)attr);
    return real_attr_getstacksize(glibc_attr, stacksize);
}

int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setguardsize(glibc_attr, guardsize);
}

/* pthread_mutexattr — macOS uses the same layout as glibc for mutexattr
 * (it's small enough), but we need to override because macOS mutex types
 * differ: PTHREAD_MUTEX_NORMAL=0, ERRORCHECK=1, RECURSIVE=2, DEFAULT=3.
 * Linux: NORMAL=0, ERRORCHECK=2, RECURSIVE=1, DEFAULT=0.
 * We pass through to glibc and translate the type. */
int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
    static int (*real)(pthread_mutexattr_t *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "pthread_mutexattr_init");
    return real(attr);
}
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
    static int (*real)(pthread_mutexattr_t *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "pthread_mutexattr_destroy");
    return real(attr);
}
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type) {
    static int (*real)(pthread_mutexattr_t *, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "pthread_mutexattr_settype");
    /* Translate macOS type to Linux type */
    int linux_type;
    switch (type) {
        case 0: linux_type = 0; break;  /* NORMAL → NORMAL */
        case 1: linux_type = 2; break;  /* ERRORCHECK → ERRORCHECK */
        case 2: linux_type = 1; break;  /* RECURSIVE → RECURSIVE */
        case 3: linux_type = 0; break;  /* DEFAULT → NORMAL */
        default: linux_type = type; break;
    }
    return real(attr, linux_type);
}

/* pthread_create — the macOS binary passes a macOS-format attr. We need
 * to extract the glibc attr from it and pass that to glibc's
 * pthread_create. If the attr is NULL, pass NULL (use default). */
static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                   void *(*)(void *), void *);

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    if (!real_pthread_create) {
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    }
    if (getenv("MACIFY_NET_DEBUG")) {
        char b[128];
        snprintf(b, sizeof(b), "pthread_create: start_routine=%p arg=%p\n",
                 (void *)start_routine, arg);
        (void)write(2, b, strlen(b));
    }
    pthread_attr_t *glibc_attr = NULL;
    if (attr) {
        struct macos_pthread_attr *ma = (struct macos_pthread_attr *)(uintptr_t)attr;
        if (ma->sig == MACOS_PTHREAD_ATTR_SIG) {
            glibc_attr = (pthread_attr_t *)ma->opaque;
        } else {
            /* Attr wasn't initialized by our pthread_attr_init — just pass
             * it through and hope for the best. */
            glibc_attr = (pthread_attr_t *)(uintptr_t)attr;
        }
    }
    return real_pthread_create(thread, glibc_attr, start_routine, arg);
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

struct ret_global_entry {
    const char *name;
    uint64_t static_addr;  /* static address of the ret_ global */
};

static const struct ret_global_entry ret_global_entries[] = {
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
