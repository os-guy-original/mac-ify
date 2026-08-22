#include "pthread_internal.h"

int (*real_attr_init)(pthread_attr_t *);
int (*real_attr_destroy)(pthread_attr_t *);
int (*real_attr_setstacksize)(pthread_attr_t *, size_t);
int (*real_attr_getstacksize)(const pthread_attr_t *, size_t *);
int (*real_attr_setguardsize)(pthread_attr_t *, size_t);
int (*real_attr_setdetachstate)(pthread_attr_t *, int);
int (*real_attr_getdetachstate)(const pthread_attr_t *, int *);
int (*real_attr_setinheritsched)(pthread_attr_t *, int);
int (*real_attr_getinheritsched)(const pthread_attr_t *, int *);
int (*real_attr_setscope)(pthread_attr_t *, int);
int (*real_attr_getscope)(const pthread_attr_t *, int *);
int (*real_attr_setstack)(pthread_attr_t *, void *, size_t);

void init_real_attr_funcs(void) {
    real_attr_init              = macify_elf_lookup("pthread_attr_init");
    real_attr_destroy           = macify_elf_lookup("pthread_attr_destroy");
    real_attr_setstacksize      = macify_elf_lookup("pthread_attr_setstacksize");
    real_attr_getstacksize      = macify_elf_lookup("pthread_attr_getstacksize");
    real_attr_setguardsize      = macify_elf_lookup("pthread_attr_setguardsize");
    real_attr_setdetachstate    = macify_elf_lookup("pthread_attr_setdetachstate");
    real_attr_getdetachstate    = macify_elf_lookup("pthread_attr_getdetachstate");
    real_attr_setinheritsched   = macify_elf_lookup("pthread_attr_setinheritsched");
    real_attr_getinheritsched   = macify_elf_lookup("pthread_attr_getinheritsched");
    real_attr_setscope          = macify_elf_lookup("pthread_attr_setscope");
    real_attr_getscope          = macify_elf_lookup("pthread_attr_getscope");
    real_attr_setstack          = macify_elf_lookup("pthread_attr_setstack");
}

#define LAZY_INIT_ATTR() do { \
    if (!real_attr_init) init_real_attr_funcs(); \
} while (0)

/* Get the glibc attr from a macOS attr. If the macOS attr doesn't have
 * our signature, allocate a new glibc attr. */
pthread_attr_t *get_glibc_attr(struct macos_pthread_attr *macos_attr) {
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
    if (getenv("MACIFY_TRACE_PTHREAD")) {
        char b[128]; int n = snprintf(b, sizeof(b), "macify: pthread_attr_init(attr=%p) -> glibc_attr=%p\n", attr, glibc_attr);
        (void)write(2, b, n);
    }
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
    int r = real_attr_setstacksize(glibc_attr, stacksize);
    if (getenv("MACIFY_TRACE_PTHREAD")) {
        char b[160]; int n = snprintf(b, sizeof(b), "macify: pthread_attr_setstacksize(attr=%p glibc=%p, size=%zu)\n", attr, (void*)glibc_attr, stacksize);
        (void)write(2, b, n);
    }
    return r;
}

int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)(uintptr_t)attr);
    int r = real_attr_getstacksize(glibc_attr, stacksize);
    if (getenv("MACIFY_TRACE_PTHREAD")) {
        char b[128]; int n = snprintf(b, sizeof(b), "macify: pthread_attr_getstacksize(attr=%p) -> size=%zu\n", attr, *stacksize);
        (void)write(2, b, n);
    }
    return r;
}

int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setguardsize(glibc_attr, guardsize);
}

/* Detachstate constants differ: macOS JOINABLE=1/DETACHED=2, Linux
 * JOINABLE=0/DETACHED=1. Ruby passes the Darwin constant straight to
 * glibc, which rejects 2 with EINVAL and aborts thread creation. */
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate) {
    if (getenv("MACIFY_TRACE_PTHREAD")) {
        unsigned char *raw = (unsigned char *)attr;
        char b[256]; int n = snprintf(b, sizeof(b), "macify: setdetachstate ENTER attr=%p raw=", attr);
        for (int i = 0; i < 24 && n < (int)sizeof(b) - 3; i++)
            n += snprintf(b + n, sizeof(b) - n, "%02x", raw[i]);
        snprintf(b + n, sizeof(b) - n, "\n");
        (void)write(2, b, strlen(b));
    }
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    if (getenv("MACIFY_TRACE_PTHREAD")) {
        char b[160]; int n = snprintf(b, sizeof(b), "macify: setdetachstate GOT  glibc=%p ds=%d\n", (void*)glibc_attr, detachstate);
        (void)write(2, b, n);
    }
    int linux_ds = (detachstate == 2) ? 1 : (detachstate == 1) ? 0 : detachstate;
    return real_attr_setdetachstate(glibc_attr, linux_ds);
}

int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)(uintptr_t)attr);
    int linux_ds = 0;
    int r = real_attr_getdetachstate(glibc_attr, &linux_ds);
    *detachstate = (linux_ds == 1) ? 2 : (linux_ds == 0) ? 1 : linux_ds;
    return r;
}

/* Inheritsched constants also diverge: macOS INHERIT=1/EXPLICIT=2,
 * Linux INHERIT=0/EXPLICIT=1. Without interposition, glibc writes its
 * policy field straight into the wrapper struct (offset 8), clobbering
 * the opaque pointer. */
int pthread_attr_setinheritsched(pthread_attr_t *attr, int inheritsched) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    int linux_ih = (inheritsched == 1) ? 0 : (inheritsched == 2) ? 1 : inheritsched;
    return real_attr_setinheritsched(glibc_attr, linux_ih);
}

int pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inheritsched) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)(uintptr_t)attr);
    int linux_ih = 0;
    int r = real_attr_getinheritsched(glibc_attr, &linux_ih);
    *inheritsched = (linux_ih == 1) ? 2 : (linux_ih == 0) ? 1 : linux_ih;
    return r;
}

/* Scope constants are identical (SYSTEM=0, PROCESS=1); interposed only
 * to route through the opaque glibc attr. */
int pthread_attr_setscope(pthread_attr_t *attr, int scope) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setscope(glibc_attr, scope);
}

int pthread_attr_getscope(const pthread_attr_t *attr, int *scope) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)(uintptr_t)attr);
    return real_attr_getscope(glibc_attr, scope);
}

/* Ruby allocates its own thread stacks and passes them via setstack. */
int pthread_attr_setstack(pthread_attr_t *attr, void *stackaddr, size_t stacksize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setstack(glibc_attr, stackaddr, stacksize);
}

/* pthread_mutexattr — macOS uses the same layout as glibc for mutexattr
 * (it's small enough), but we need to override because macOS mutex types
 * differ: PTHREAD_MUTEX_NORMAL=0, ERRORCHECK=1, RECURSIVE=2, DEFAULT=3.
 * Linux: NORMAL=0, ERRORCHECK=2, RECURSIVE=1, DEFAULT=0.
 * We pass through to glibc and translate the type. */
