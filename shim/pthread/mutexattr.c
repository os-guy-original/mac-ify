#include "pthread_internal.h"

int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
    static int (*real)(pthread_mutexattr_t *) = NULL;
    if (!real) real = real_dlsym(RTLD_NEXT, "pthread_mutexattr_init");
    return real(attr);
}
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
    static int (*real)(pthread_mutexattr_t *) = NULL;
    if (!real) real = real_dlsym(RTLD_NEXT, "pthread_mutexattr_destroy");
    return real(attr);
}
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type) {
    static int (*real)(pthread_mutexattr_t *, int) = NULL;
    if (!real) real = real_dlsym(RTLD_NEXT, "pthread_mutexattr_settype");
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
 * pthread_create. If the attr is NULL, pass NULL (use default).
 *
 * We also wrap start_routine to set up a signal stack (sigaltstack) for
 * each new thread. Without this, signals (SIGSEGV, SIGURG, etc.) can't
 * be delivered to Go-created threads, causing the process to be killed. */

/* Thread start wrapper: sets up sigaltstack then calls the real routine. */
struct thread_start_args {
    void *(*start_routine)(void *);
    void *arg;
};

