#include "pthread_internal.h"

int (*real_attr_init)(pthread_attr_t *);
int (*real_attr_destroy)(pthread_attr_t *);
int (*real_attr_setstacksize)(pthread_attr_t *, size_t);
int (*real_attr_getstacksize)(const pthread_attr_t *, size_t *);
int (*real_attr_setguardsize)(pthread_attr_t *, size_t);

void init_real_attr_funcs(void) {
    real_attr_init         = macify_elf_lookup("pthread_attr_init");
    real_attr_destroy      = macify_elf_lookup("pthread_attr_destroy");
    real_attr_setstacksize = macify_elf_lookup("pthread_attr_setstacksize");
    real_attr_getstacksize = macify_elf_lookup("pthread_attr_getstacksize");
    real_attr_setguardsize = macify_elf_lookup("pthread_attr_setguardsize");
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
        char b[128]; int n = snprintf(b, sizeof(b), "macify: pthread_attr_setstacksize(attr=%p, size=%zu)\n", attr, stacksize);
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

/* pthread_mutexattr — macOS uses the same layout as glibc for mutexattr
 * (it's small enough), but we need to override because macOS mutex types
 * differ: PTHREAD_MUTEX_NORMAL=0, ERRORCHECK=1, RECURSIVE=2, DEFAULT=3.
 * Linux: NORMAL=0, ERRORCHECK=2, RECURSIVE=1, DEFAULT=0.
 * We pass through to glibc and translate the type. */
