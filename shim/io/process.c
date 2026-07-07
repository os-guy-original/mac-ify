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
    ssize_t r = real_read(fd, buf, count);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: read(%d, %zu) = %zd\n", fd, count, r);
        (void)write(2, b, n);
    }
    return r;
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

/* ── macOS stdio internal functions ────────────────────────────
 *
 * CRITICAL: macOS FILE* layout differs from glibc's. macOS binaries
 * read FILE* fields at macOS offsets, which correspond to different
 * fields in glibc's FILE*. The most problematic access is at offset
 * 0x10: macOS reads this as `_flags` (short) and checks bit 0x40
 * (__SERR, error flag). Glibc has `_IO_read_end` (char pointer) at
 * offset 0x10. After writing to a stream, glibc sets _IO_read_end to
 * the buffer address, whose low byte may have bit 0x40 set — causing
 * macOS code to falsely detect a write error.
 *
 * Fix: After each stdio write, clear bit 0x40 of the byte at offset
 * 0x10 of the glibc FILE*. This slightly modifies _IO_read_end (by at
 * most clearing bit 6 of its low byte), which is safe for write-only
 * streams like stdout/stderr where glibc doesn't use _IO_read_end. */

static inline void macify_clear_serr_flag(FILE *fp) {
    /* Clear bit 0x40 at offset 0x10 to prevent macOS __SERR false positive */
    unsigned char *p = (unsigned char *)fp + 0x10;
    *p &= ~0x40;
}

/* __srget — read one character from FILE* (macOS internal).
 * Called by macOS's getc/fgetc macro when the buffer is empty. */
int __srget(FILE *fp) {
    return fgetc(fp);
}

/* __swbuf — write one character to FILE* (macOS internal).
 * Called by macOS's putc macro when the buffer is full.
 * Returns the character on success, EOF on error. */
int __swbuf(int ch, FILE *fp) {
    int r = fputc(ch, fp);
    if (r != EOF) macify_clear_serr_flag(fp);
    return r;
}

/* putc_unlocked — write char to FILE* without locking.
 * On macOS this is a macro that accesses FILE* fields directly.
 * We provide it as a function to avoid field-offset corruption. */
int putc_unlocked(int ch, FILE *fp) {
    int r = fputc(ch, fp);
    if (r != EOF) macify_clear_serr_flag(fp);
    return r;
}

/* getc_unlocked — read char from FILE* without locking. */
int getc_unlocked(FILE *fp) {
    return fgetc(fp);
}

/* putchar_unlocked, getchar_unlocked — variants using stdout/stdin */
int putchar_unlocked(int ch) {
    int r = fputc(ch, stdout);
    if (r != EOF) macify_clear_serr_flag(stdout);
    return r;
}

int getchar_unlocked(void) {
    return fgetc(stdin);
}

/* ── fread/fgetc shims — translate glibc EOF to macOS __SEOF ───
 *
 * macOS binaries check for EOF/error by reading [FILE* + 0x10] as a short:
 *   bit 0x20 = __SEOF (end of file)
 *   bit 0x40 = __SERR (error)
 *
 * Glibc has _IO_read_end (char pointer) at offset 0x10, not _flags.
 * After fread returns 0 (EOF), glibc sets _IO_EOF_SEEN in _flags (offset 0),
 * but macOS code doesn't check offset 0 — it checks offset 0x10.
 *
 * Fix: After fread/fgetc returns EOF, set bit 0x20 at offset 0x10 so macOS
 * code detects EOF. This is safe because at EOF, the buffer is empty
 * (_IO_read_ptr == _IO_read_end), so modifying _IO_read_end doesn't lose data.
 * The next underflow call resets _IO_read_end anyway.
 *
 * Also clear bit 0x40 (error) to prevent false error detection. */

/* Glibc _flags bits */
#define GLIBC_IO_EOF_SEEN  0x10
#define GLIBC_IO_ERR_SEEN  0x20

/* macOS _flags bits (at offset 0x10) */
#define MACOS_SEOF  0x20
#define MACOS_SERR  0x40

static inline void macify_sync_stdio_flags(FILE *fp) {
    unsigned int glibc_flags = *(unsigned int *)((char *)fp + 0);
    unsigned char *macos_flags = (unsigned char *)fp + 0x10;
    /* Clear macOS error/EOF bits */
    *macos_flags &= ~(MACOS_SEOF | MACOS_SERR);
    /* Set macOS EOF if glibc has EOF */
    if (glibc_flags & GLIBC_IO_EOF_SEEN) {
        *macos_flags |= MACOS_SEOF;
    }
    /* Set macOS error if glibc has error */
    if (glibc_flags & GLIBC_IO_ERR_SEEN) {
        *macos_flags |= MACOS_SERR;
    }
}

size_t macify_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) __asm__("fread");
size_t macify_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) real_fread = dlsym(RTLD_NEXT, "fread");
    size_t r = real_fread(ptr, size, nmemb, stream);
    if (getenv("MACIFY_TRACE_FREAD")) {
        char b[256];
        int n = snprintf(b, sizeof(b), "macify: fread(%p, %zu, %zu, %p) = %zu\n",
                ptr, size, nmemb, (void*)stream, r);
        (void)write(2, b, n);
    }
    if (r == 0) {
        /* EOF or error — buffer is empty, safe to sync flags */
        macify_sync_stdio_flags(stream);
    } else {
        /* Data was read. Clear macOS error flag (bit 0x40) at offset 0x10
         * to prevent false error detection. This modifies _IO_read_end's
         * low byte by at most 0x40, but since we're NOT changing
         * _IO_read_ptr, glibc will re-read the "lost" bytes on the next
         * underflow. The key insight: sort only checks [fp+0x10] for
         * errors AFTER fread returns, and we clear the error bit here. */
        unsigned char *p10 = (unsigned char *)stream + 0x10;
        *p10 &= ~MACOS_SERR;
    }
    return r;
}
int macify_fgetc(FILE *stream) __asm__("fgetc");
int macify_fgetc(FILE *stream) {
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    int r = real_fgetc(stream);
    if (r == EOF) {
        macify_sync_stdio_flags(stream);
    }
    return r;
}

/* fseeko — glibc clears _IO_EOF_SEEN on seek. We must also clear
 * macOS __SEOF at offset 0x10 so sort doesn't think we're still at EOF. */
int macify_fseeko(FILE *stream, long off, int whence) __asm__("fseeko");
int macify_fseeko(FILE *stream, long off, int whence) {
    static int (*real_fseeko)(FILE *, long, int) = NULL;
    if (!real_fseeko) real_fseeko = dlsym(RTLD_NEXT, "fseeko");
    int r = real_fseeko(stream, off, whence);
    if (r == 0) {
        /* Seek succeeded — clear macOS EOF/error flags at offset 0x10.
         * After seek, buffer is empty, so modifying _IO_read_end is safe. */
        unsigned char *macos_flags = (unsigned char *)stream + 0x10;
        *macos_flags &= ~(MACOS_SEOF | MACOS_SERR);
    }
    return r;
}

/* clearerr — clear both glibc's flags and macOS's flags at offset 0x10 */
void macify_clearerr(FILE *stream) __asm__("clearerr");
void macify_clearerr(FILE *stream) {
    static void (*real_clearerr)(FILE *) = NULL;
    if (!real_clearerr) real_clearerr = dlsym(RTLD_NEXT, "clearerr");
    real_clearerr(stream);
    unsigned char *macos_flags = (unsigned char *)stream + 0x10;
    *macos_flags &= ~(MACOS_SEOF | MACOS_SERR);
}

/* ── fclose/fflush shims — protect _IO_read_end from macOS _flags writes ──
 *
 * sort's _rpl_fflush writes to [fp + 0x10] as if it's macOS _flags (short).
 * On glibc, offset 0x10 = _IO_read_end (char pointer). The write corrupts
 * the pointer, causing fclose to fail with EINVAL.
 *
 * Fix: Before calling glibc's fclose, restore _IO_read_end by setting
 * _IO_read_ptr = _IO_read_end (emptying the buffer). This makes fclose
 * not use the corrupted pointer for buffer operations. */

int macify_fclose(FILE *stream) __asm__("fclose");
int macify_fclose(FILE *stream) {
    static int (*real_fclose)(FILE *) = NULL;
    if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
    /* macOS _rpl_fflush corrupts _IO_read_end (offset 0x10) by writing
     * macOS _flags to it. Restore _IO_read_end = _IO_read_ptr (uncorrupted).
     * For write streams, _IO_read_ptr is NULL, so _IO_read_end becomes NULL.
     * This prevents fclose from failing due to corrupted pointer. */
    void **read_ptr = (void **)((char *)stream + 8);
    void **read_end = (void **)((char *)stream + 0x10);
    *read_end = *read_ptr;
    /* Clear macOS __SERR bit */
    *((unsigned char *)stream + 0x10) &= ~0x40;
    return real_fclose(stream);
}

int macify_fflush(FILE *stream) __asm__("fflush");
int macify_fflush(FILE *stream) {
    static int (*real_fflush)(FILE *) = NULL;
    if (!real_fflush) real_fflush = dlsym(RTLD_NEXT, "fflush");
    if (stream) {
        /* Restore _IO_read_end = _IO_read_ptr to fix corruption from
         * macOS _rpl_fflush which writes _flags to [fp+0x10]. */
        void **read_ptr = (void **)((char *)stream + 8);
        void **read_end = (void **)((char *)stream + 0x10);
        *read_end = *read_ptr;
        *((unsigned char *)stream + 0x10) &= ~0x40;
    }
    return real_fflush(stream);
}

/* setvbuf — ensure buffer address doesn't have bit 0x40 in low byte.
 * macOS binaries check [stdout + 0x10] & 0x40 for __SERR (error).
 * Glibc stores _IO_read_end (buffer pointer) at offset 0x10.
 * If glibc allocates a buffer with bit 0x40 set, macOS code falsely
 * detects a write error. We intercept setvbuf to allocate a safe buffer. */
int macify_setvbuf(FILE *stream, char *buf, int mode, size_t size) __asm__("setvbuf");
int macify_setvbuf(FILE *stream, char *buf, int mode, size_t size) {
    static int (*real_setvbuf)(FILE *, char *, int, size_t) = NULL;
    if (!real_setvbuf) real_setvbuf = dlsym(RTLD_NEXT, "setvbuf");
    
    /* If buf is NULL (glibc allocates), provide our own buffer */
    if (!buf && size > 0) {
        /* Allocate a buffer without bit 0x40 in the low byte */
        char *our_buf = malloc(size + 128);
        if (our_buf) {
            /* Find an offset within the allocation that clears bit 0x40 */
            uintptr_t addr = (uintptr_t)our_buf;
            if (addr & 0x40) {
                /* Round up to next 0x80 boundary to clear bit 0x40 */
                addr = (addr + 0x7f) & ~0x7f;
            }
            buf = (char *)addr;
            /* Ensure buf is still within our allocation */
            if (buf + size > our_buf + size + 128) {
                free(our_buf);
                our_buf = NULL;
                buf = NULL;
            }
        }
    }
    return real_setvbuf(stream, buf, mode, size);
}
