/* flags.c — macOS/Linux flag translation and low-level I/O overrides
 * (mmap, open, madvise, mprotect, munmap, fcntl) */
#include "io_internal.h"
#include <errno.h>
#include <string.h>

int macify_net_debug_enabled = -1;

void macify_net_dbg(const char *msg) {
    if (macify_net_debug_enabled < 0) {
        const char *e = getenv("MACIFY_NET_DEBUG");
        macify_net_debug_enabled = (e && e[0]) ? 1 : 0;
    }
    if (macify_net_debug_enabled) {
        (void)write(2, msg, strlen(msg));
    }
}

void macify_net_dbg_hex(const char *prefix, const void *p, int n) {
    if (macify_net_debug_enabled < 0) {
        const char *e = getenv("MACIFY_NET_DEBUG");
        macify_net_debug_enabled = (e && e[0]) ? 1 : 0;
    }
    if (!macify_net_debug_enabled) return;
    char buf[512];
    int off = 0;
    off += snprintf(buf + off, sizeof(buf) - off, "%s", prefix);
    const uint8_t *b = (const uint8_t *)p;
    for (int i = 0; i < n && i < 32; i++) {
        off += snprintf(buf + off, sizeof(buf) - off, " %02x", b[i]);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\n");
    (void)write(2, buf, off);
}

unsigned int translate_open_flags(unsigned int macos_flags) {
    unsigned int linux_flags = macos_flags & 0x3;
    if (macos_flags & MACOS_O_CREAT)     linux_flags |= LINUX_O_CREAT;
    if (macos_flags & MACOS_O_EXCL)      linux_flags |= LINUX_O_EXCL;
    if (macos_flags & MACOS_O_TRUNC)     linux_flags |= LINUX_O_TRUNC;
    if (macos_flags & MACOS_O_APPEND)    linux_flags |= LINUX_O_APPEND;
    if (macos_flags & MACOS_O_NONBLOCK)  linux_flags |= LINUX_O_NONBLOCK;
    if (macos_flags & MACOS_O_NOCTTY)    linux_flags |= LINUX_O_NOCTTY;
    if (macos_flags & MACOS_O_SYNC)      linux_flags |= LINUX_O_SYNC;
    if (macos_flags & MACOS_O_CLOEXEC)   linux_flags |= LINUX_O_CLOEXEC;
    if (macos_flags & MACOS_O_DIRECTORY) linux_flags |= LINUX_O_DIRECTORY;
    if (macos_flags & MACOS_O_NOFOLLOW)  linux_flags |= LINUX_O_NOFOLLOW;
    return linux_flags;
}

int translate_fcntl_cmd(int cmd) {
    switch (cmd) {
        case MACOS_F_GETLK:         return LINUX_F_GETLK;
        case MACOS_F_SETLK:         return LINUX_F_SETLK;
        case MACOS_F_SETLKW:        return LINUX_F_SETLKW;
        case MACOS_F_DUPFD_CLOEXEC: return LINUX_F_DUPFD_CLOEXEC;
        default: return cmd;
    }
}

void * (*real_mmap)(void *, size_t, int, int, int, off_t);
int    (*real_open)(const char *, int, ...);
int    (*real_madvise)(void *, size_t, int);
int    (*real_fcntl)(int, int, ...);
int    (*real_mprotect)(void *, size_t, int);

void init_real_io_funcs(void) {
    real_mmap     = dlsym(RTLD_NEXT, "mmap");
    real_open     = dlsym(RTLD_NEXT, "open");
    real_madvise  = dlsym(RTLD_NEXT, "madvise");
    real_fcntl    = dlsym(RTLD_NEXT, "fcntl");
    real_mprotect = dlsym(RTLD_NEXT, "mprotect");
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    LAZY_INIT_IO();
    void *orig_addr = addr;
    int orig_flags = flags;
    if (flags & MACOS_MAP_ANON) {
        flags = (flags & ~MACOS_MAP_ANON) | LINUX_MAP_ANONYMOUS;
        fd = -1;
    }
    if ((flags & 0x10) && addr != NULL) {
        size_t page_size = sysconf(_SC_PAGESIZE);
        uintptr_t a = (uintptr_t)addr;
        size_t adjustment = a % page_size;
        if (adjustment != 0) {
            addr = (void *)(a - adjustment);
            length += adjustment;
            if (offset != 0) offset -= adjustment;
        }
    }
    void *result = real_mmap(addr, length, prot, flags, fd, offset);
    if (result == (void *)-1) {
        /* MAP_FIXED failure: return orig_addr to match macOS behavior.
         * On macOS, MAP_FIXED at an already-mapped address silently
         * replaces the existing mapping. On Linux, this also works
         * (MAP_FIXED replaces). But some callers check the return value
         * and panic if it's MAP_FAILED. Returning orig_addr is a
         * workaround that lets the caller proceed.
         *
         * This is needed for Rust binaries that use MAP_FIXED for thread
         * stack allocation: they mmap a large region with PROT_NONE,
         * then MAP_FIXED a smaller region inside it with PROT_READ|WRITE.
         * If the inner MAP_FIXED fails (which shouldn't happen but can
         * due to address space layout), returning orig_addr lets Rust
         * continue instead of panicking. */
        if ((orig_flags & 0x10) && orig_addr != NULL) return orig_addr;
    } else if ((orig_flags & 0x10) && result != orig_addr) {
        return orig_addr;
    }
    if (prot == 0 && macify_main_stack_base && result != (void *)-1) {
        uintptr_t stack_lo = (uintptr_t)macify_main_stack_base;
        uintptr_t stack_hi = stack_lo + macify_main_stack_size;
        uintptr_t mmap_lo = (uintptr_t)result;
        uintptr_t mmap_hi = mmap_lo + length;
        if (mmap_lo >= stack_lo && mmap_hi <= stack_hi) {
            real_mprotect(result, length, 0x1 | 0x2);
        }
    }
    return result;
}

int open(const char *pathname, int flags, ...) {
    LAZY_INIT_IO();
    mode_t mode = 0;
    int linux_flags;
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (is_macos) {
        linux_flags = (int)translate_open_flags((unsigned int)flags);
    } else {
        linux_flags = flags;
    }
    if (linux_flags & LINUX_O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

    const char *effective_path = pathname;
    char translated_path[4096];
    if (is_macos) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) {
            errno = ENOENT;
            return -1;
        }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, translated_path, sizeof(translated_path)) == 0) {
            effective_path = translated_path;
        }
    }

    int fd = real_open(effective_path, linux_flags, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512];
        int n = snprintf(b, sizeof(b), "macify: open(\"%s\"%s, 0x%x->0x%x) = %d\n",
                pathname,
                effective_path != pathname ? " [translated]" : "",
                flags, linux_flags, fd);
        (void)write(2, b, n);
    }
    return fd;
}

/* open64 — glibc's 64-bit offset variant of open.
 * Rust's std::fs::File::open uses open64 on 64-bit Linux.
 * Without this shim, bat's file opens bypass our path translation
 * and flag translation. */
int macify_open64(const char *pathname, int flags, ...) __asm__("open64");
int macify_open64(const char *pathname, int flags, ...) {
    LAZY_INIT_IO();
    mode_t mode = 0;
    int linux_flags;
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (is_macos) {
        linux_flags = (int)translate_open_flags((unsigned int)flags);
    } else {
        linux_flags = flags;
    }
    if (linux_flags & LINUX_O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

    const char *effective_path = pathname;
    char translated_path[4096];
    if (is_macos) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) {
            errno = ENOENT;
            return -1;
        }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, translated_path, sizeof(translated_path)) == 0) {
            effective_path = translated_path;
        }
    }

    static int (*real_open64)(const char *, int, ...) = NULL;
    if (!real_open64) real_open64 = dlsym(RTLD_NEXT, "open64");
    int fd = real_open64(effective_path, linux_flags, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512];
        int n = snprintf(b, sizeof(b), "macify: open64(\"%s\"%s, 0x%x->0x%x) = %d\n",
                pathname,
                effective_path != pathname ? " [translated]" : "",
                flags, linux_flags, fd);
        (void)write(2, b, n);
    }
    return fd;
}

/* __open_2 — glibc's _FORTIFY_SOURCE variant of open.
 * Used when compile-time flag checking is enabled. */
int macify___open_2(const char *pathname, int flags) __asm__("__open_2");
int macify___open_2(const char *pathname, int flags) {
    return open(pathname, flags);
}

/* __open64_2 — glibc's _FORTIFY_SOURCE variant of open64. */
int macify___open64_2(const char *pathname, int flags) __asm__("__open64_2");
int macify___open64_2(const char *pathname, int flags) {
    return macify_open64(pathname, flags);
}

/* openat — like open but relative to a directory fd.
 * macOS AT_FDCWD = -2, Linux AT_FDCWD = -100.
 * Also translates macOS open flags and applies prefix path translation. */
int openat(int dirfd, const char *pathname, int flags, ...) {
    LAZY_INIT_IO();
    mode_t mode = 0;
    int linux_flags;
    int linux_dirfd = dirfd;
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (is_macos) {
        linux_flags = (int)translate_open_flags((unsigned int)flags);
        if (dirfd == -2) linux_dirfd = -100;  /* AT_FDCWD */
    } else {
        linux_flags = flags;
    }
    if (linux_flags & LINUX_O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

    /* Prefix path translation */
    const char *effective_path = pathname;
    char translated_path[4096];
    if (is_macos) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, translated_path, sizeof(translated_path)) == 0) {
            effective_path = translated_path;
        }
    }

    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    int fd = real_openat(linux_dirfd, effective_path, linux_flags, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: openat(%d, \"%s\"%s, 0x%x->0x%x) = %d\n",
            dirfd, pathname ? pathname : "(null)",
            effective_path != pathname ? " [translated]" : "",
            flags, linux_flags, fd);
        (void)write(2, b, n);
    }
    return fd;
}

int madvise(void *addr, size_t length, int advice) {
    LAZY_INIT_IO();
    if (advice == MACOS_MADV_FREE) advice = LINUX_MADV_FREE;
    return real_madvise(addr, length, advice);
}

int mprotect(void *addr, size_t len, int prot) {
    LAZY_INIT_IO();
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t a = (uintptr_t)addr;
    size_t adjustment = a % page_size;
    if (adjustment != 0) {
        addr = (void *)(a - adjustment);
        len += adjustment;
    }
    if (prot == 0 && macify_main_stack_base) {
        uintptr_t stack_lo = (uintptr_t)macify_main_stack_base;
        uintptr_t stack_hi = stack_lo + macify_main_stack_size;
        uintptr_t prot_lo = (uintptr_t)addr;
        uintptr_t prot_hi = prot_lo + len;
        if (prot_lo >= stack_lo && prot_hi <= stack_hi) return 0;
    }
    return real_mprotect(addr, len, prot);
}

int munmap(void *addr, size_t length) {
    if (macify_main_stack_base) {
        uintptr_t stack_lo = (uintptr_t)macify_main_stack_base;
        uintptr_t stack_hi = stack_lo + macify_main_stack_size;
        uintptr_t unmap_lo = (uintptr_t)addr;
        uintptr_t unmap_hi = unmap_lo + length;
        if (unmap_lo < stack_hi && unmap_hi > stack_lo) return 0;
    }
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");
    int ret = real_munmap(addr, length);
    if (getenv("MACIFY_MACH_DEBUG") && ret != 0) {
        char b[160];
        int n = snprintf(b, sizeof(b),
            "macify: munmap(%p, %zu) = %d (errno=%d %s)\n",
            addr, length, ret, errno, strerror(errno));
        (void)write(2, b, n);
    }
    return ret;
}
