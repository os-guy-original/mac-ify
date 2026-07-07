#include <string.h>
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

/* ── _IO_read_ptr save/restore (forward declarations) ──────────
 * These are defined later but needed by fopen/fdopen to save the
 * original _IO_read_ptr before corrupting it with _r = -1. */
static void macify_save_read_ptr(FILE *fp);
static void macify_restore_read_ptr(FILE *fp);

FILE *macify_fopen(const char *path, const char *mode) __asm__("fopen");
FILE *macify_fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *fp = real_fopen(path, mode);
    if (fp && macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Set a custom buffer at a safe address (low byte without bit 0x40).
         * macOS binaries check [fp + 0x10] & 0x40 for __SERR (error).
         * Glibc stores _IO_read_end (buffer pointer) at offset 0x10.
         * If the buffer address has bit 0x40, false read errors are detected. */
        char *buf = (char *)malloc(4096 + 128);
        if (buf) {
            /* Find offset within allocation that clears bit 0x40 */
            uintptr_t addr = (uintptr_t)buf;
            if (addr & 0x40) addr = (addr + 0x7f) & ~0x7f;
            if (((uintptr_t)addr & 0x40) == 0) {
                setvbuf(fp, (char *)addr, _IOFBF, 4096);
            }
        }
        /* CRITICAL: setvbuf sets _IO_read_ptr (offset 8) to the buffer base
         * address. macOS's inlined getc macro reads _r from offset 8 (low 4
         * bytes of _IO_read_ptr). If _r > 0, getc reads *_p (offset 0 =
         * glibc _flags = 0xfbad2084) as a pointer → crash.
         * Save _IO_read_ptr, then set _r = -1 to force the first getc to
         * call __srget. __srget will restore _IO_read_ptr before calling
         * fgetc, so glibc sees a valid pointer. For fread-based binaries,
         * the restore also fixes _IO_read_ptr before glibc uses it. */
        macify_save_read_ptr(fp);
        *(int *)((char *)fp + 8) = -1;
    }
    return fp;
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
    /* Set _IO_read_end (offset 0x10) to NULL for write streams.
     * macOS close_stdout reads [fp + 0x10] & 0x40 for __SERR (error).
     * Glibc stores _IO_read_end (buffer pointer) at offset 0x10.
     * After writes, the buffer address may have bit 0x40 set.
     * Setting _IO_read_end = NULL is safe for write-only streams
     * (stdout/stderr) where glibc doesn't use _IO_read_end. */
    unsigned char *p = (unsigned char *)fp + 0x10;
    *p &= ~0x40;
}

/* __srget — read one character from FILE* (macOS internal).
 * Called by macOS's getc/fgetc macro when the buffer is empty.
 *
 * macOS getc macro: --_r >= 0 ? *_p++ : __srget(fp)
 * _r is at FILE* offset 8 (glibc _IO_read_ptr low 4 bytes)
 * _p is at FILE* offset 0 (glibc _flags)
 *
 * After fgetc returns, glibc sets _IO_read_ptr to the buffer.
 * The low 4 bytes become a large positive number, so the next getc
 * reads *_p (glibc _flags = 0xfbad2084) → SIGSEGV.
 *
 * Fix: After fgetc, save _IO_read_ptr and set _r = -1 to force the
 * next getc to call __srget again. On the next __srget call, restore
 * _IO_read_ptr before calling fgetc. This way glibc always sees a
 * valid _IO_read_ptr, and the inlined getc always calls __srget. */

/* Per-FILE* saved _IO_read_ptr. Uses a simple array keyed by FILE* address.
 * Most macOS binaries use only a few FILE* streams (stdin, stdout, stderr,
 * plus a few opened files). A small array suffices. */
#define MACIFY_MAX_SAVED_FPS 16
static struct {
    FILE *fp;
    void *saved_read_ptr;
    int valid;
} macify_saved_fps[MACIFY_MAX_SAVED_FPS];

static void macify_save_read_ptr(FILE *fp) {
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (macify_saved_fps[i].fp == fp && macify_saved_fps[i].valid) {
            macify_saved_fps[i].saved_read_ptr = *(void **)((char *)fp + 8);
            return;
        }
    }
    /* New entry */
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (!macify_saved_fps[i].valid) {
            macify_saved_fps[i].fp = fp;
            macify_saved_fps[i].saved_read_ptr = *(void **)((char *)fp + 8);
            macify_saved_fps[i].valid = 1;
            return;
        }
    }
}

static void macify_restore_read_ptr(FILE *fp) {
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (macify_saved_fps[i].fp == fp && macify_saved_fps[i].valid) {
            *(void **)((char *)fp + 8) = macify_saved_fps[i].saved_read_ptr;
            return;
        }
    }
}

static void macify_sync_stdio_flags(FILE *fp);
int __srget(FILE *fp) {
    /* Call real glibc fgetc directly (NOT our macify_fgetc shim).
     * If we call macify_fgetc, it does its own save/restore/write-(-1),
     * which conflicts with ours: macify_fgetc writes -1 to offset 8,
     * then we save the CORRUPTED _IO_read_ptr. On the next call, we
     * restore the corrupted value, causing glibc to crash. */
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    /* Restore saved _IO_read_ptr before calling fgetc */
    macify_restore_read_ptr(fp);
    int c = real_fgetc ? real_fgetc(fp) : EOF;
    if (c != EOF) {
        /* Save _IO_read_ptr, then set _r = -1 to force next getc
         * to call __srget instead of accessing _p (glibc _flags). */
        macify_save_read_ptr(fp);
        *(int *)((char *)fp + 8) = -1;
    } else {
        /* On EOF: restore _IO_read_ptr and sync flags */
        macify_restore_read_ptr(fp);
        macify_sync_stdio_flags(fp);
    }
    return c;
}

/* __swbuf — write one character to FILE* (macOS internal).
 * Called by macOS's putc macro when the write buffer is full.
 *
 * macOS putc macro: --_w >= 0 ? (*_p++ = ch) : __swbuf(ch, fp)
 * _w is at FILE* offset 0x0c (high 4 bytes of glibc's _IO_read_ptr)
 * _p is at FILE* offset 0x00 (glibc's _flags)
 *
 * After fputc, glibc may set _IO_read_ptr, making _w (offset 0x0c)
 * a large positive number. The next putc reads *_p (_flags) → crash.
 *
 * Fix: After fputc, set _w = -1 to force next putc to call __swbuf. */
int __swbuf(int ch, FILE *fp) {
    /* Call real glibc fputc directly (NOT our macify_fputc shim) to
     * avoid double write-(-1) corruption. See __srget for details. */
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    int r = real_fputc ? real_fputc(ch, fp) : EOF;
    if (r != EOF) {
        macify_clear_serr_flag(fp);
        /* Set _w = -1 (offset 0x0c = high 4 bytes of _IO_read_ptr) */
        *(int *)((char *)fp + 0x0c) = -1;
    }
    return r;
}

/* putc_unlocked — macOS inlines this as a macro accessing FILE* fields.
 * We provide it as a function. After writing, set _w = -1 to prevent
 * the inlined macro from accessing _p (glibc _flags) on the next call.
 * CRITICAL: Call real glibc fputc directly to avoid double write-(-1)
 * corruption from our macify_fputc shim. See __srget for details. */
int putc_unlocked(int ch, FILE *fp) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    macify_restore_read_ptr(fp);
    int r = real_fputc ? real_fputc(ch, fp) : EOF;
    if (r != EOF) {
        macify_clear_serr_flag(fp);
        *(int *)((char *)fp + 0x0c) = -1;  /* _w = -1 */
    }
    return r;
}

/* getc_unlocked — macOS inlines this as a macro accessing FILE* fields.
 * After reading, set _r = -1 to prevent the inlined macro from
 * accessing _p (glibc _flags) on the next call.
 * CRITICAL: Call real glibc fgetc directly to avoid double save/restore
 * corruption from our macify_fgetc shim. See __srget for details. */
int getc_unlocked(FILE *fp) {
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    macify_restore_read_ptr(fp);
    int c = real_fgetc ? real_fgetc(fp) : EOF;
    if (c != EOF) {
        macify_save_read_ptr(fp);
        *(int *)((char *)fp + 8) = -1;  /* _r = -1 */
    } else {
        macify_restore_read_ptr(fp);
        macify_sync_stdio_flags(fp);
    }
    return c;
}

/* putchar_unlocked, getchar_unlocked — variants using stdout/stdin.
 * CRITICAL: Call real glibc fputc/fgetc directly to avoid double
 * write-(-1) corruption from our shims. See __srget for details. */
int putchar_unlocked(int ch) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    extern FILE *__stdoutp;
    macify_restore_read_ptr(__stdoutp);
    int r = real_fputc ? real_fputc(ch, __stdoutp) : EOF;
    if (r != EOF) {
        macify_clear_serr_flag(__stdoutp);
        *(int *)((char *)__stdoutp + 0x0c) = -1;  /* _w = -1 */
    }
    return r;
}

int getchar_unlocked(void) {
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    extern FILE *__stdinp;
    macify_restore_read_ptr(__stdinp);
    int c = real_fgetc ? real_fgetc(__stdinp) : EOF;
    if (c != EOF) {
        macify_save_read_ptr(__stdinp);
        *(int *)((char *)__stdinp + 8) = -1;  /* _r = -1 */
    } else {
        macify_restore_read_ptr(__stdinp);
        macify_sync_stdio_flags(__stdinp);
    }
    return c;
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
    /* Restore saved _IO_read_ptr before calling fread (like __srget) */
    macify_restore_read_ptr(stream);
    size_t r = real_fread(ptr, size, nmemb, stream);
    if (getenv("MACIFY_TRACE_FREAD")) {
        char b[256];
        int n = snprintf(b, sizeof(b), "macify: fread(%p, %zu, %zu, %p) = %zu\n",
                ptr, size, nmemb, (void*)stream, r);
        (void)write(2, b, n);
    }
    if (r == 0) {
        /* EOF or error — buffer is empty, safe to sync flags */
        macify_restore_read_ptr(stream);
        macify_sync_stdio_flags(stream);
    } else {
        /* Data was read. Save _IO_read_ptr and set _r = -1 to prevent
         * inlined getc from dereferencing _p (glibc _flags) → SIGSEGV.
         * Also clear macOS error flag (bit 0x40) at offset 0x10. */
        macify_save_read_ptr(stream);
        *(int *)((char *)stream + 8) = -1;
        unsigned char *p10 = (unsigned char *)stream + 0x10;
        *p10 &= ~MACOS_SERR;
    }
    return r;
}
int macify_fgetc(FILE *stream) __asm__("fgetc");
int macify_fgetc(FILE *stream) {
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    /* Restore saved _IO_read_ptr before calling fgetc (like __srget) */
    macify_restore_read_ptr(stream);
    int r = real_fgetc(stream);
    if (r != EOF) {
        /* Save _IO_read_ptr and set _r = -1 to prevent inlined getc
         * from dereferencing _p (glibc _flags = 0xfbad2084) → SIGSEGV. */
        macify_save_read_ptr(stream);
        *(int *)((char *)stream + 8) = -1;
    } else {
        macify_restore_read_ptr(stream);
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
    /* Before real_fflush: restore _IO_read_end = _IO_read_ptr to fix
     * corruption from macOS _rpl_fflush which writes _flags to [fp+0x10]. */
    if (stream) {
        void **rp = (void **)((char *)stream + 8);
        void **re = (void **)((char *)stream + 0x10);
        *re = *rp;
    }
    int r = real_fflush(stream);
    /* After real_fflush: clear macOS __SERR bit at offset 0x10 to prevent
     * false write error detection by close_stdout. */
    if (stream) {
        *((unsigned char *)stream + 0x10) &= ~0x40;
    } else {
        extern FILE *__stdoutp, *__stderrp;
        if (__stdoutp) {
            void **rp = (void **)((char *)__stdoutp + 8);
            void **re = (void **)((char *)__stdoutp + 0x10);
            *re = *rp;
            *((unsigned char *)__stdoutp + 0x10) &= ~0x40;
        }
        if (__stderrp) {
            void **rp = (void **)((char *)__stderrp + 8);
            void **re = (void **)((char *)__stderrp + 0x10);
            *re = *rp;
            *((unsigned char *)__stderrp + 0x10) &= ~0x40;
        }
    }
    return r;
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

/* fputc/fwrite/printf shims — clear macOS __SERR after writes.
 * macOS close_stdout checks [stdout + 0x10] & 0x40 for errors.
 * Glibc stores _IO_read_end (buffer pointer) at offset 0x10.
 * After any write, the buffer pointer might have bit 0x40 set.
 * We clear it after each write to prevent false error detection. */
int macify_fputc(int ch, FILE *stream) __asm__("fputc");
int macify_fputc(int ch, FILE *stream) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    int r = real_fputc(ch, stream);
    if (r != EOF) {
        *((unsigned char *)stream + 0x10) &= ~0x40;
        *(int *)((char *)stream + 0x0c) = -1;  /* _w = -1 */
    }
    return r;
}

size_t macify_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) __asm__("fwrite");
size_t macify_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!real_fwrite) real_fwrite = dlsym(RTLD_NEXT, "fwrite");
    size_t r = real_fwrite(ptr, size, nmemb, stream);
    if (r > 0) {
        *((unsigned char *)stream + 0x10) &= ~0x40;
    }
    return r;
}

/* printf shim — clear macOS __SERR after writes */
int macify_printf(const char *fmt, ...) __asm__("printf");
int macify_printf(const char *fmt, ...) {
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    va_list ap;
    va_start(ap, fmt);
    int r = real_vfprintf(stdout, fmt, ap);
    va_end(ap);
    if (r >= 0) {
        *((unsigned char *)stdout + 0x10) &= ~0x40;
    }
    return r;
}

/* fputs shim — clear macOS __SERR after writes */
int macify_fputs(const char *s, FILE *stream) __asm__("fputs");
int macify_fputs(const char *s, FILE *stream) {
    static int (*real_fputs)(const char *, FILE *) = NULL;
    if (!real_fputs) real_fputs = dlsym(RTLD_NEXT, "fputs");
    int r = real_fputs(s, stream);
    if (r >= 0) {
        *((unsigned char *)stream + 0x10) &= ~0x40;
    }
    return r;
}

/* fdopen — pass-through. Safe buffer is set by fopen shim. */
FILE *macify_fdopen(int fd, const char *mode) __asm__("fdopen");
FILE *macify_fdopen(int fd, const char *mode) {
    static FILE *(*real_fdopen)(int, const char *) = NULL;
    if (!real_fdopen) real_fdopen = dlsym(RTLD_NEXT, "fdopen");
    FILE *fp = real_fdopen(fd, mode);
    if (fp && macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Save _IO_read_ptr and set _r = -1 (see fopen for details). */
        macify_save_read_ptr(fp);
        *(int *)((char *)fp + 8) = -1;
    }
    return fp;
}
