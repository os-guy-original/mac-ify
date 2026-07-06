/* shim_symbol.c — macify_get_shim_symbol: return shim override for dlsym */
#include "signal_internal.h"
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>


/* macify_get_shim_symbol — return our shim's override for a given symbol.
 * Used by dl.c's dlsym override to ensure Go (and other binaries) get our
 * translated functions instead of glibc's.
 *
 * CRITICAL: Go's runtime uses dlsym to look up C functions. If it gets
 * glibc's pthread_mutex_lock directly, it bypasses our macOS mutex
 * conversion, causing crashes (macOS mutex signature 0x32AAABA7 is
 * misinterpreted by glibc as "already locked").
 *
 * We must return our shim's override for ALL functions that translate
 * between macOS and Linux data layouts. */
void *macify_get_shim_symbol(const char *symbol) {
    /* Signal-related functions */
    if (strcmp(symbol, "sigaction") == 0) {
        extern int sigaction(int, const struct sigaction *, struct sigaction *);
        return (void *)sigaction;
    }
    if (strcmp(symbol, "sigaltstack") == 0) {
        return (void *)macify_sigaltstack;
    }
    if (strcmp(symbol, "signal") == 0) {
        return (void *)macify_signal;
    }

    /* Pthread mutex/cond functions — macOS objects have different layout */
    if (strcmp(symbol, "pthread_mutex_lock") == 0) {
        extern int pthread_mutex_lock(pthread_mutex_t *);
        return (void *)pthread_mutex_lock;
    }
    if (strcmp(symbol, "pthread_mutex_trylock") == 0) {
        extern int pthread_mutex_trylock(pthread_mutex_t *);
        return (void *)pthread_mutex_trylock;
    }
    if (strcmp(symbol, "pthread_mutex_unlock") == 0) {
        extern int pthread_mutex_unlock(pthread_mutex_t *);
        return (void *)pthread_mutex_unlock;
    }
    if (strcmp(symbol, "pthread_mutex_init") == 0) {
        extern int pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
        return (void *)pthread_mutex_init;
    }
    if (strcmp(symbol, "pthread_mutex_destroy") == 0) {
        extern int pthread_mutex_destroy(pthread_mutex_t *);
        return (void *)pthread_mutex_destroy;
    }
    if (strcmp(symbol, "pthread_cond_wait") == 0) {
        extern int pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
        return (void *)pthread_cond_wait;
    }
    if (strcmp(symbol, "pthread_cond_timedwait") == 0) {
        extern int pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
        return (void *)pthread_cond_timedwait;
    }
    if (strcmp(symbol, "pthread_cond_signal") == 0) {
        extern int pthread_cond_signal(pthread_cond_t *);
        return (void *)pthread_cond_signal;
    }
    if (strcmp(symbol, "pthread_cond_broadcast") == 0) {
        extern int pthread_cond_broadcast(pthread_cond_t *);
        return (void *)pthread_cond_broadcast;
    }
    if (strcmp(symbol, "pthread_cond_init") == 0) {
        extern int pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
        return (void *)pthread_cond_init;
    }
    if (strcmp(symbol, "pthread_cond_destroy") == 0) {
        extern int pthread_cond_destroy(pthread_cond_t *);
        return (void *)pthread_cond_destroy;
    }

    /* Pthread signal mask */
    if (strcmp(symbol, "pthread_sigmask") == 0) {
        extern int macify_pthread_sigmask(int, const void *, void *) __asm__("pthread_sigmask");
        return (void *)macify_pthread_sigmask;
    }
    if (strcmp(symbol, "sigprocmask") == 0) {
        extern int macify_sigprocmask(int, const void *, void *) __asm__("sigprocmask");
        return (void *)macify_sigprocmask;
    }
    if (strcmp(symbol, "pthread_kill") == 0) {
        extern int macify_pthread_kill(pthread_t, int) __asm__("pthread_kill");
        return (void *)macify_pthread_kill;
    }

    /* sigset functions (4-byte macOS vs 128-byte Linux) */
    if (strcmp(symbol, "sigaddset") == 0) {
        extern int sigaddset(sigset_t *, int);
        return (void *)sigaddset;
    }
    if (strcmp(symbol, "sigdelset") == 0) {
        extern int sigdelset(sigset_t *, int);
        return (void *)sigdelset;
    }
    if (strcmp(symbol, "sigemptyset") == 0) {
        extern int sigemptyset(sigset_t *);
        return (void *)sigemptyset;
    }
    if (strcmp(symbol, "sigfillset") == 0) {
        extern int sigfillset(sigset_t *);
        return (void *)sigfillset;
    }
    if (strcmp(symbol, "sigismember") == 0) {
        extern int sigismember(const sigset_t *, int);
        return (void *)sigismember;
    }

    /* kqueue/kevent */
    if (strcmp(symbol, "kqueue") == 0) {
        extern int kqueue(void);
        return (void *)kqueue;
    }
    if (strcmp(symbol, "kevent") == 0) {
        extern int kevent(int, const void *, int, void *, int, const void *);
        return (void *)kevent;
    }

    /* mlock/munlock — Go locks signal stack pages, may fail without CAP_IPC_LOCK */
    if (strcmp(symbol, "mlock") == 0) {
        extern int mlock(const void *, size_t);
        return (void *)mlock;
    }
    if (strcmp(symbol, "munlock") == 0) {
        extern int munlock(const void *, size_t);
        return (void *)munlock;
    }
    if (strcmp(symbol, "mlockall") == 0) {
        extern int mlockall(int);
        return (void *)mlockall;
    }
    if (strcmp(symbol, "munlockall") == 0) {
        extern int munlockall(void);
        return (void *)munlockall;
    }

    return NULL;
}
