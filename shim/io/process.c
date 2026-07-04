/* process.c — process management: fork, clone, wait4, pipe, read, write,
 * writev, readv, fopen */
#include "io_internal.h"
#include <sys/uio.h>
#include <sys/wait.h>
#include <poll.h>

int macify_wait4(int pid, int *status, int options, void *rusage) __asm__("wait4");
int macify_wait4(int pid, int *status, int options, void *rusage) {
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        static pid_t (*real_wait4)(pid_t, int *, int, void *) = NULL;
        if (!real_wait4) real_wait4 = dlsym(RTLD_NEXT, "wait4");
        if (real_wait4) return real_wait4(pid, status, options, rusage);
    }
    errno = 10;
    return -1;
}

pid_t macify_fork(void) __asm__("fork");
pid_t macify_fork(void) {
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        static pid_t (*real_fork)(void) = NULL;
        if (!real_fork) real_fork = dlsym(RTLD_NEXT, "fork");
        if (real_fork) return real_fork();
    }
    errno = 38;
    return -1;
}

pid_t macify_vfork(void) __asm__("vfork");
pid_t macify_vfork(void) { errno = 38; return -1; }

long macify_clone(unsigned long flags, void *stack, int *parent_tid,
                  int *child_tid, unsigned long tls, void *newsp) __asm__("__clone");
long macify_clone(unsigned long flags, void *stack, int *parent_tid,
                  int *child_tid, unsigned long tls, void *newsp) {
    if (flags & 0x10000) {
        static long (*real_clone)(unsigned long, void *, int *, int *, unsigned long, void *) = NULL;
        if (!real_clone) real_clone = dlsym(RTLD_NEXT, "__clone");
        if (real_clone) return real_clone(flags, stack, parent_tid, child_tid, tls, newsp);
    }
    if ((flags & 0xFF) == 17 && !(flags & 0x10000)) {
        if (macify_caller_is_macos_text(__builtin_return_address(0))) {
            static long (*real_clone)(unsigned long, void *, int *, int *, unsigned long, void *) = NULL;
            if (!real_clone) real_clone = dlsym(RTLD_NEXT, "__clone");
            if (real_clone) return real_clone(flags, stack, parent_tid, child_tid, tls, newsp);
        }
    }
    errno = 38;
    return -1;
}

long macify_clone_alias(unsigned long flags, void *stack, int *parent_tid,
                        int *child_tid, unsigned long tls, void *newsp) __asm__("clone");
long macify_clone_alias(unsigned long flags, void *stack, int *parent_tid,
                        int *child_tid, unsigned long tls, void *newsp) {
    return macify_clone(flags, stack, parent_tid, child_tid, tls, newsp);
}

int macify_pipe(int *pipefd) __asm__("pipe");
int macify_pipe(int *pipefd) {
    static int (*real_pipe)(int *) = NULL;
    if (!real_pipe) real_pipe = dlsym(RTLD_NEXT, "pipe");
    return real_pipe(pipefd);
}

/* read — if reading from a pipe (FIFO) and no data is available,
 * return EOF. This prevents deadlocks when glibc's NSS tries to
 * fork helper processes (which are blocked by our clone override).
 * Without this, the parent blocks forever waiting for data from
 * a child that can never write. */
ssize_t macify_read(int fd, void *buf, size_t count) __asm__("read");
ssize_t macify_read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    /* Check if fd is a pipe (FIFO) */
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode)) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 0);
        if (pr == 0) return 0; /* No data — pipe has no writer */
    }
    return real_read(fd, buf, count);
}

ssize_t macify_write(int fd, const void *buf, size_t count) __asm__("write");
ssize_t macify_write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    ssize_t r = real_write(fd, buf, count);
    if (r == -1 && macify_caller_is_macos_text(__builtin_return_address(0)))
        errno = macify_linux_to_macos_errno(errno);
    return r;
}

ssize_t macify_writev(int fd, const struct iovec *iov, int iovcnt) __asm__("writev");
ssize_t macify_writev(int fd, const struct iovec *iov, int iovcnt) {
    static ssize_t (*real_writev)(int, const struct iovec *, int) = NULL;
    if (!real_writev) real_writev = dlsym(RTLD_NEXT, "writev");
    return real_writev(fd, iov, iovcnt);
}

ssize_t macify_readv(int fd, const struct iovec *iov, int iovcnt) __asm__("readv");
ssize_t macify_readv(int fd, const struct iovec *iov, int iovcnt) {
    static ssize_t (*real_readv)(int, const struct iovec *, int) = NULL;
    if (!real_readv) real_readv = dlsym(RTLD_NEXT, "readv");
    return real_readv(fd, iov, iovcnt);
}

FILE *macify_fopen(const char *path, const char *mode) __asm__("fopen");
FILE *macify_fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(path, mode);
}

int macify_msync(void *addr, size_t length, int flags) __asm__("msync");
int macify_msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync) real_msync = dlsym(RTLD_NEXT, "msync");
    /* Round address to page boundary */
    size_t ps = sysconf(_SC_PAGESIZE);
    uintptr_t a = (uintptr_t)addr;
    size_t adj = a % ps;
    int r = real_msync((void *)(a - adj), length + adj, flags);
    if (r == -1 && (errno == EINVAL || errno == ENOMEM)) {
        errno = 0;
        return 0; /* macOS is more lenient */
    }
    return r;
}
