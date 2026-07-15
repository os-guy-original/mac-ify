/* core.c — clock_gettime, OSSpinLock, atfork, setname, kill, getname, cond_timedwait_relative */
#include "pthread_internal.h"
#include <time.h>
#include <sched.h>

#define MACOS_CLOCK_MONOTONIC             6
#define MACOS_CLOCK_PROCESS_CPUTIME_ID   12
#define MACOS_CLOCK_THREAD_CPUTIME_ID    16
#define MACOS_CLOCK_UPTIME_RAW           8
#define MACOS_CLOCK_MONOTONIC_RAW        4

int macify_clock_gettime(int clk_id, struct timespec *tp) __asm__("clock_gettime");
int macify_clock_gettime(int clk_id, struct timespec *tp) {
    switch (clk_id) {
        case MACOS_CLOCK_MONOTONIC: clk_id = CLOCK_MONOTONIC; break;
        case MACOS_CLOCK_PROCESS_CPUTIME_ID: clk_id = CLOCK_PROCESS_CPUTIME_ID; break;
        case MACOS_CLOCK_THREAD_CPUTIME_ID: clk_id = CLOCK_THREAD_CPUTIME_ID; break;
        case MACOS_CLOCK_UPTIME_RAW:
        case MACOS_CLOCK_MONOTONIC_RAW: clk_id = CLOCK_MONOTONIC_RAW; break;
    }
    static int (*real_clock_gettime)(int, struct timespec *) = NULL;
    if (!real_clock_gettime) real_clock_gettime = macify_elf_lookup("clock_gettime");
    if (!real_clock_gettime) { errno = ENOSYS; return -1; }
    return real_clock_gettime(clk_id, tp);
}

int _pthread_getname_np(pthread_t thread, char *name, size_t len) {
    return pthread_getname_np(thread, name, len);
}

void OSSpinLockLock(volatile int32_t *lock) {
    while (__sync_lock_test_and_set(lock, 1)) { while (*lock) __asm__ volatile("pause"); }
}
void OSSpinLockUnlock(volatile int32_t *lock) { __sync_lock_release(lock); }
int OSSpinLockTry(volatile int32_t *lock) { return __sync_lock_test_and_set(lock, 1) == 0; }

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void)) {
    static int (*real_atfork)(void (*)(void), void (*)(void), void (*)(void)) = NULL;
    if (!real_atfork) {
        real_atfork = dlvsym(RTLD_NEXT, "pthread_atfork", "GLIBC_2.2.5");
        if (!real_atfork) real_atfork = macify_elf_lookup("pthread_atfork");
    }
    if (!real_atfork) return ENOSYS;
    return real_atfork(prepare, parent, child);
}

int pthread_threadid_np(pthread_t thread, uint64_t *thread_id) {
    (void)thread;
    if (thread_id) *thread_id = (uint64_t)syscall(186);
    return 0;
}

int macify_pthread_setname_np(const char *name) __asm__("pthread_setname_np");
int macify_pthread_setname_np(const char *name) {
    static int (*real_setname)(pthread_t, const char *) = NULL;
    if (!real_setname) {
        real_setname = dlvsym(RTLD_NEXT, "pthread_setname_np", "GLIBC_2.2.5");
        if (!real_setname) real_setname = macify_elf_lookup("pthread_setname_np");
    }
    if (real_setname) return real_setname(pthread_self(), name);
    return 0;
}

int macify_pthread_kill(pthread_t thread, int sig) __asm__("pthread_kill");
int macify_pthread_kill(pthread_t thread, int sig) {
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        int linux_sig = macos_sig_to_linux_signal(sig);
        if (linux_sig > 0) sig = linux_sig;
    }
    static int (*real_pthread_kill)(pthread_t, int) = NULL;
    if (!real_pthread_kill) real_pthread_kill = macify_elf_lookup("pthread_kill");
    if (!real_pthread_kill) return -1;
    return real_pthread_kill(thread, sig);
}

int macify_pthread_getname_np(pthread_t thread, char *name, size_t len) __asm__("pthread_getname_np");
int macify_pthread_getname_np(pthread_t thread, char *name, size_t len) {
    static int (*real_getname)(pthread_t, char *, size_t) = NULL;
    if (!real_getname) {
        real_getname = dlvsym(RTLD_NEXT, "pthread_getname_np", "GLIBC_2.2.5");
        if (!real_getname) real_getname = macify_elf_lookup("pthread_getname_np");
    }
    if (real_getname) return real_getname(thread, name, len);
    if (name && len > 0) name[0] = '\0';
    return 0;
}

int pthread_cond_timedwait_relative_np(pthread_cond_t *c, pthread_mutex_t *m,
                                        const struct timespec *reltime) {
    if (!reltime) return pthread_cond_wait(c, m);
    struct timespec abstime;
    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_sec += reltime->tv_sec;
    abstime.tv_nsec += reltime->tv_nsec;
    if (abstime.tv_nsec >= 1000000000) { abstime.tv_sec++; abstime.tv_nsec -= 1000000000; }
    return pthread_cond_timedwait(c, m, &abstime);
}
