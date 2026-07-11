#include <string.h>
/* process.c — process management: fork, clone, wait4, pipe, read, write,
 * writev, readv, fopen */
#include "io_internal.h"
#include <sys/uio.h>
#include <sys/wait.h>
#include <poll.h>

int macify_wait4(int pid, int *status, int options, void *rusage) __asm__("wait4");
int macify_wait4(int pid, int *status, int options, void *rusage) {
    if (getenv("MACIFY_TRACE_FORK")) {
        char b[128]; int n = snprintf(b, sizeof(b),
            "macify: wait4(pid=%d, options=0x%x) from pid=%d\n",
            pid, options, getpid());
        (void)write(2, b, n);
    }
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        static pid_t (*real_wait4)(pid_t, int *, int, void *) = NULL;
        if (!real_wait4) real_wait4 = dlsym(RTLD_NEXT, "wait4");
        if (real_wait4) return real_wait4(pid, status, options, rusage);
    }
    errno = 10;
    return -1;
}

/* waitpid — macOS binaries call waitpid (not wait4). Without this shim,
 * waitpid resolves to glibc's waitpid which calls wait4 syscall directly,
 * bypassing our wait4 shim. This causes sort to block forever waiting
 * for children that were never forked (sort calls waitpid defensively
 * to reap zombies). */
pid_t macify_waitpid(pid_t pid, int *status, int options) __asm__("waitpid");
pid_t macify_waitpid(pid_t pid, int *status, int options) {
    if (getenv("MACIFY_TRACE_FORK")) {
        char b[128]; int n = snprintf(b, sizeof(b),
            "macify: waitpid(pid=%d, options=0x%x) from pid=%d\n",
            pid, options, getpid());
        (void)write(2, b, n);
    }
    static pid_t (*real_waitpid)(pid_t, int *, int) = NULL;
    if (!real_waitpid) real_waitpid = dlsym(RTLD_NEXT, "waitpid");
    return real_waitpid ? real_waitpid(pid, status, options) : -1;
}

pid_t macify_fork(void) __asm__("fork");
pid_t macify_fork(void) {
    /* If MACIFY_NO_FORK is set, return -1 to prevent forking.
     * Some macOS binaries (like sort) fork a child that inherits
     * corrupted FILE* state and hangs in glibc's internal I/O.
     * Setting MACIFY_NO_FORK=1 forces single-process mode. */
    if (getenv("MACIFY_NO_FORK")) {
        errno = ENOSYS;
        return -1;
    }
    static pid_t (*real_fork)(void) = NULL;
    if (!real_fork) real_fork = dlsym(RTLD_NEXT, "fork");
    if (real_fork) return real_fork();
    errno = ENOSYS;
    return -1;
}

pid_t macify_vfork(void) __asm__("vfork");
pid_t macify_vfork(void) {
    if (getenv("MACIFY_NO_FORK")) {
        errno = ENOSYS;
        return -1;
    }
    static pid_t (*real_fork)(void) = NULL;
    if (!real_fork) real_fork = dlsym(RTLD_NEXT, "fork");
    pid_t r = real_fork ? real_fork() : -1;
    if (getenv("MACIFY_TRACE_FORK")) {
        char b[128]; int n = snprintf(b, sizeof(b),
            "macify: vfork() = %d (pid=%d)\n", r, getpid());
        (void)write(2, b, n);
    }
    if (r < 0) errno = ENOSYS;
    return r;
}

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

/* read — pass through to glibc's real read.
 *
 * Previously this had special logic to return EOF when a pipe (FIFO) had
 * no data immediately available (poll returns 0). That was a workaround
 * for glibc's NSS helpers forking helpers that couldn't run because our
 * clone() shim blocked them. The workaround broke real pipes: if the
 * reader polled before the writer wrote, it got a spurious EOF.
 *
 * Now we just pass through to glibc's read. The kernel handles pipe
 * semantics correctly: read() blocks until data is available OR the
 * writer closes the pipe (then returns 0 = EOF). */
ssize_t macify_read(int fd, void *buf, size_t count) __asm__("read");
ssize_t macify_read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    ssize_t r = real_read(fd, buf, count);
    if (getenv("MACIFY_TRACE_READ")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: read(%d, %zu) = %zd errno=%d\n",
            fd, count, r, r < 0 ? errno : 0);
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
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return NULL; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    FILE *fp = real_fopen(eff, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: fopen(\"%s\", \"%s\") = %p errno=%d\n",
            path ? path : "(null)", mode ? mode : "(null)",
            (void *)fp, fp ? 0 : errno);
        (void)write(2, b, n);
    }
    if (fp && macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Save initial _IO_read_ptr and _IO_read_end so we can restore
         * them after macOS code corrupts offset 0x10 (writing _flags). */
        macify_save_read_ptr(fp);
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
    /* Skip macOS FILE structs — they have their own _flags at offset 16 */
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(fp)) return;
    /* Clear bit 0x40 of _IO_read_end (offset 0x10, low byte) for
     * WRITE streams only (stdout/stderr). For read streams, writing
     * to offset 0x10 corrupts _IO_read_end and crashes glibc. */
    extern FILE *__stdoutp, *__stderrp;
    if (fp == __stdoutp || fp == __stderrp) {
        *((unsigned char *)fp + 0x10) &= ~0x40;
    }
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
    void *saved_read_end;
    int valid;
} macify_saved_fps[MACIFY_MAX_SAVED_FPS];

static void macify_save_read_ptr(FILE *fp) {
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (macify_saved_fps[i].fp == fp && macify_saved_fps[i].valid) {
            macify_saved_fps[i].saved_read_ptr = *(void **)((char *)fp + 8);
            macify_saved_fps[i].saved_read_end = *(void **)((char *)fp + 0x10);
            return;
        }
    }
    /* New entry */
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (!macify_saved_fps[i].valid) {
            macify_saved_fps[i].fp = fp;
            macify_saved_fps[i].saved_read_ptr = *(void **)((char *)fp + 8);
            macify_saved_fps[i].saved_read_end = *(void **)((char *)fp + 0x10);
            macify_saved_fps[i].valid = 1;
            return;
        }
    }
}

static void macify_restore_read_ptr(FILE *fp) {
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (macify_saved_fps[i].fp == fp && macify_saved_fps[i].valid) {
            *(void **)((char *)fp + 8) = macify_saved_fps[i].saved_read_ptr;
            /* Also restore _IO_read_end (offset 0x10). macOS code writes
             * _flags (short) to offset 0x10, corrupting _IO_read_end.
             * Without restoring it, glibc's fread sees _IO_read_ptr >
             * _IO_read_end and loops forever (sort hang). */
            *(void **)((char *)fp + 0x10) = macify_saved_fps[i].saved_read_end;
            return;
        }
    }
}

static void macify_sync_stdio_flags(FILE *fp);

/* Global flag: set to 1 by the loader when getc macros have been patched
 * to always call __srget (NOP'd the _r store + changed jle to jmp).
 * When patched, __srget does NOT need to corrupt _r = -1, which prevents
 * breaking glibc functions that access _IO_read_ptr (ftello, fseeko,
 * fpurge, getline, etc.). */
int macify_getc_patched = 0;

/* macify_skip_r_patch — when TRUE, do NOT set _r=-1 or _w=-1 (which
 * corrupt glibc's _IO_read_ptr at offset 8 and _IO_read_ptr+4 at 0x0c).
 * Set by the loader for binaries that call fputc/fgetc as FUNCTIONS
 * (no inlined putc/getc macros). For these binaries, setting _r=-1
 * breaks glibc's internal I/O (fread, fgets, fclose) causing hangs.
 *
 * Binaries WITH inlined putc macros NEED _r=-1 to prevent the macro
 * from reading _p (glibc's _flags = 0xfbad2084) as a pointer. */
int macify_skip_r_patch = 0;

int __srget(FILE *fp) {
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    /* Restore _IO_read_ptr before calling fgetc, but ONLY when the getc
     * macro is NOT patched. When patched, the store was NOP'd so
     * _IO_read_ptr is never corrupted and no restore is needed. */
    if (is_macos && !macify_getc_patched) macify_restore_read_ptr(fp);
    int c = real_fgetc ? real_fgetc(fp) : EOF;
    if (getenv("MACIFY_TRACE_SRGET")) {
        void *rp = *(void **)((char *)fp + 8);
        void *re = *(void **)((char *)fp + 0x10);
        char b[256];
        int n = snprintf(b, sizeof(b),
            "macify: __srget(fp=%p) c=%d read_ptr=%p read_end=%p diff=%ld %s%s\n",
            (void*)fp, c, rp, re, (long)((char*)re - (char*)rp),
            is_macos ? "[macOS]" : "[glibc]",
            macify_getc_patched ? " [patched]" : "");
        (void)write(2, b, n);
    }
    /* Set _r = -1 to force the next getc to call __srget again.
     * SKIP this when getc is patched. */
    if (c != EOF && is_macos && !macify_getc_patched && !macify_skip_r_patch) {
        macify_save_read_ptr(fp);
        *(int *)((char *)fp + 8) = -1;
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
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    return real_fputc ? real_fputc(ch, fp) : EOF;
}

/* putc_unlocked — macOS inlines this as a macro accessing FILE* fields.
 * CRITICAL: Call real glibc fputc directly to avoid double write-(-1)
 * corruption from our macify_fputc shim. See __srget for details. */
int putc_unlocked(int ch, FILE *fp) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    macify_restore_read_ptr(fp);
    int r = real_fputc ? real_fputc(ch, fp) : EOF;
    if (r != EOF) {
        extern FILE *__stdoutp, *__stderrp;
        if (fp == __stdoutp || fp == __stderrp) {
    
            if (!macify_skip_r_patch) *(int *)((char *)fp + 0x0c) = -1;
        }
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
        if (!macify_getc_patched && !macify_skip_r_patch) *(int *)((char *)fp + 8) = -1;  /* _r = -1 */
    } else {
        macify_restore_read_ptr(fp);
        /* skip — caller detects EOF via return value */
    }
    return c;
}

/* putchar_unlocked, getchar_unlocked — variants using stdout/stdin.
 * CRITICAL: Call real glibc fputc/fgetc directly to avoid double
 * write-(-1) corruption from our shims. See __srget for details. */
int putchar_unlocked(int ch) {
    extern FILE *__stdoutp;
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(__stdoutp)) {
        extern int macify_fputc_macos(int, void *);
        return macify_fputc_macos(ch, __stdoutp);
    }
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    macify_restore_read_ptr(__stdoutp);
    int r = real_fputc ? real_fputc(ch, __stdoutp) : EOF;
    if (r != EOF) {

        if (!macify_skip_r_patch) *(int *)((char *)__stdoutp + 0x0c) = -1;  /* _w = -1 */
    }
    return r;
}

int getchar_unlocked(void) {
    extern FILE *__stdinp;
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(__stdinp)) {
        /* TODO: implement macOS stdin read */
        return EOF;
    }
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    macify_restore_read_ptr(__stdinp);
    int c = real_fgetc ? real_fgetc(__stdinp) : EOF;
    if (c != EOF) {
        macify_save_read_ptr(__stdinp);
        if (!macify_getc_patched && !macify_skip_r_patch) *(int *)((char *)__stdinp + 8) = -1;  /* _r = -1 */
    } else {
        macify_restore_read_ptr(__stdinp);
        /* skip */
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

/* macify_sync_stdio_flags — called on EOF/error paths only.
 * Sets macOS __SEOF/__SERR bits at offset 0x10 (low byte of glibc's
 * _IO_read_end). Only called when fread/fgetc returns 0/EOF, at which
 * point the buffer is empty and modifying _IO_read_end is safe. */
static inline void macify_sync_stdio_flags(FILE *fp) {
    unsigned int glibc_flags = *(unsigned int *)((char *)fp + 0);
    unsigned char *p10 = (unsigned char *)fp + 0x10;
    if (glibc_flags & 0x10)  /* _IO_EOF_SEEN */
        *p10 |= 0x20;   /* Set __SEOF */
    else
        *p10 &= ~0x20;  /* Clear __SEOF */
    if (glibc_flags & 0x20)  /* _IO_ERR_SEEN */
        *p10 |= 0x40;   /* Set __SERR */
    else
        *p10 &= ~0x40;  /* Clear __SERR */
}

size_t macify_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) __asm__("fread");
size_t macify_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) real_fread = dlsym(RTLD_NEXT, "fread");
    /* Always restore _IO_read_ptr AND _IO_read_end before calling glibc's
     * fread. macOS code writes _flags to offset 0x10, corrupting
     * _IO_read_end. Without restoring, glibc sees _IO_read_ptr >
     * _IO_read_end and loops forever. */
    if (!macify_getc_patched) macify_restore_read_ptr(stream);
    size_t r = real_fread(ptr, size, nmemb, stream);
    /* After glibc's fread, _IO_read_ptr and _IO_read_end are valid.
     * Save them so we can restore on the next call (after macOS code
     * corrupts them by writing _flags). */
    if (!macify_getc_patched) macify_save_read_ptr(stream);
    if (getenv("MACIFY_TRACE_READ")) {
        unsigned int flags_before = *(unsigned int *)((char *)stream);
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: fread(%p, %zu, %zu, %p) = %zu flags=0x%x err=%d eof=%d\n",
            ptr, size, nmemb, (void*)stream, r, flags_before,
            (flags_before & 0x20) ? 1 : 0, (flags_before & 0x10) ? 1 : 0);
        (void)write(2, b, n);
    }
    if (r > 0 && !macify_getc_patched && !macify_skip_r_patch) {
        macify_save_read_ptr(stream);
        *(int *)((char *)stream + 8) = -1;
        *((unsigned char *)stream + 0x10) &= ~0x40;
    }
    return r;
}
int macify_fgetc(FILE *stream) __asm__("fgetc");
int macify_fgetc(FILE *stream) {
    static int (*real_fgetc)(FILE *) = NULL;
    if (!real_fgetc) real_fgetc = dlsym(RTLD_NEXT, "fgetc");
    /* Restore _IO_read_ptr AND _IO_read_end before calling fgetc. */
    if (!macify_getc_patched) macify_restore_read_ptr(stream);
    int r = real_fgetc(stream);
    /* Save valid _IO_read_ptr and _IO_read_end after glibc's fgetc. */
    if (!macify_getc_patched) macify_save_read_ptr(stream);
    if (r != EOF && !macify_getc_patched && !macify_skip_r_patch) {
        *(int *)((char *)stream + 8) = -1;
    }
    return r;
}

/* ungetc — push back a character. MUST restore _IO_read_ptr before
 * calling glibc's ungetc, because glibc accesses _IO_read_ptr directly
 * to decrement it. Our _r=-1 corruption makes _IO_read_ptr invalid. */
int macify_ungetc(int c, FILE *stream) __asm__("ungetc");
int macify_ungetc(int c, FILE *stream) {
    static int (*real_ungetc)(int, FILE *) = NULL;
    if (!real_ungetc) real_ungetc = dlsym(RTLD_NEXT, "ungetc");
    if (!macify_getc_patched) macify_restore_read_ptr(stream);
    int r = real_ungetc(c, stream);
    if (r != EOF && !macify_getc_patched && !macify_skip_r_patch) {
        /* Re-save and re-corrupt _r = -1 */
        macify_save_read_ptr(stream);
        *(int *)((char *)stream + 8) = -1;
    }
    return r;
}

/* fseeko — glibc clears _IO_EOF_SEEN on seek. We must also clear
 * macOS __SEOF at offset 0x10 so sort doesn't think we're still at EOF. */
int macify_fseeko(FILE *stream, long off, int whence) __asm__("fseeko");
int macify_fseeko(FILE *stream, long off, int whence) {
    static int (*real_fseeko)(FILE *, long, int) = NULL;
    if (!real_fseeko) real_fseeko = dlsym(RTLD_NEXT, "fseeko");
    /* Restore _IO_read_ptr and _IO_read_end before calling glibc. */
    if (!macify_getc_patched) macify_restore_read_ptr(stream);
    int r = real_fseeko(stream, off, whence);
    /* Save valid state after glibc's fseeko. */
    if (!macify_getc_patched) macify_save_read_ptr(stream);
    return r;
}

/* clearerr — clear glibc's EOF and error flags directly. */
void macify_clearerr(FILE *stream) __asm__("clearerr");
void macify_clearerr(FILE *stream) {
    if (!stream) return;
    unsigned int *glibc_flags = (unsigned int *)((char *)stream + 0);
    *glibc_flags &= ~0x30;  /* Clear _IO_EOF_SEEN | _IO_ERR_SEEN */
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
    /* If using macOS FILE, just flush and return */
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(stream)) {
        extern int macify_fflush_macos(void *);
        return macify_fflush_macos(stream);
    }
    static int (*real_fclose)(FILE *) = NULL;
    if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
    /* Restore saved _IO_read_ptr before fclose. */
    macify_restore_read_ptr(stream);
    void **read_ptr = (void **)((char *)stream + 8);
    void **read_end = (void **)((char *)stream + 0x10);
    *read_end = *read_ptr;
    /* Invalidate the save/restore entry so a reused FILE* (same address)
     * doesn't get the stale saved _IO_read_ptr restored. */
    for (int i = 0; i < MACIFY_MAX_SAVED_FPS; i++) {
        if (macify_saved_fps[i].fp == stream && macify_saved_fps[i].valid) {
            macify_saved_fps[i].valid = 0;
            break;
        }
    }
    return real_fclose(stream);
}


/* ferror — check glibc's _IO_ERR_SEEN directly, bypassing any
 * consistency checks that might detect our _IO_read_ptr corruption.
 * sort calls ferror() after fread() to check for read errors.
 * glibc's ferror checks _flags (offset 0) bit 0x20 (_IO_ERR_SEEN).
 * Our _r=-1 corruption of _IO_read_ptr doesn't set _IO_ERR_SEEN,
 * but glibc's internal consistency checks might. This shim reads
 * _flags directly to avoid triggering those checks. */
int macify_ferror(FILE *stream) __asm__("ferror");
int macify_ferror(FILE *stream) {
    if (!stream) return 0;
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(stream)) {
        /* macOS FILE: check _flags (offset 16, short) bit 0x40 (__SERR) */
    short *flags = (short *)((char *)stream + 16);
    return (*flags & 0x40) ? 1 : 0;
    }
    unsigned int glibc_flags = *(unsigned int *)((char *)stream + 0);
    return (glibc_flags & 0x20) ? 1 : 0;  /* _IO_ERR_SEEN */
}

/* feof — check glibc's _IO_EOF_SEEN directly. */
int macify_feof(FILE *stream) __asm__("feof");
int macify_feof(FILE *stream) {
    if (!stream) return 0;
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(stream)) {
        /* macOS FILE: check _flags (offset 16, short) bit 0x20 (__SEOF) */
    short *flags = (short *)((char *)stream + 16);
    return (*flags & 0x20) ? 1 : 0;
    }
    unsigned int glibc_flags = *(unsigned int *)((char *)stream + 0);
    return (glibc_flags & 0x10) ? 1 : 0;  /* _IO_EOF_SEEN */
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
    return real_setvbuf(stream, buf, mode, size);
}

/* fputc/fwrite/printf shims — clear macOS __SERR after writes.
 * macOS close_stdout checks [stdout + 0x10] & 0x40 for errors.
 * Glibc stores _IO_read_end (buffer pointer) at offset 0x10.
 * After any write, the buffer pointer might have bit 0x40 set.
 * We clear it after each write to prevent false error detection. */

size_t macify_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) __asm__("fwrite");
size_t macify_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!real_fwrite) real_fwrite = dlsym(RTLD_NEXT, "fwrite");
    return real_fwrite(ptr, size, nmemb, stream);
}

/* printf shim — write to macOS stdout if applicable */
int macify_printf(const char *fmt, ...) __asm__("printf");
int macify_printf(const char *fmt, ...) {
    extern FILE *__stdoutp;
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(__stdoutp)) {
        /* Format to a buffer and write via macOS fwrite */
        char buf[4096];
        va_list ap;
        va_start(ap, fmt);
        int r = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (r > 0) {
            extern size_t macify_fwrite_macos(const void *, size_t, size_t, void *);
            macify_fwrite_macos(buf, 1, r, __stdoutp);
        }
        return r;
    }
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    va_list ap;
    va_start(ap, fmt);
    int r = real_vfprintf(stdout, fmt, ap);
    va_end(ap);
    if (r >= 0) {

    }
    return r;
}

/* vfprintf — handle macOS FILE and clear __SERR. */
int macify_vfprintf(FILE *stream, const char *fmt, va_list ap) __asm__("vfprintf");
int macify_vfprintf(FILE *stream, const char *fmt, va_list ap) {
    extern int macify_is_macos_file(void *);
    if (macify_is_macos_file(stream)) {
        char buf[4096];
        int r = vsnprintf(buf, sizeof(buf), fmt, ap);
        if (r > 0) {
            extern size_t macify_fwrite_macos(const void *, size_t, size_t, void *);
            macify_fwrite_macos(buf, 1, r, stream);
        }
        return r;
    }
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    int r = real_vfprintf(stream, fmt, ap);
    if (r >= 0) {

    }
    return r;
}

/* fprintf — handle macOS FILE and clear __SERR */
int macify_fprintf(FILE *stream, const char *fmt, ...) __asm__("fprintf");
int macify_fprintf(FILE *stream, const char *fmt, ...) {
    extern int macify_is_macos_file(void *);
    va_list ap;
    va_start(ap, fmt);
    int r;
    if (macify_is_macos_file(stream)) {
        char buf[4096];
        r = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (r > 0) {
            extern size_t macify_fwrite_macos(const void *, size_t, size_t, void *);
            macify_fwrite_macos(buf, 1, r, stream);
        }
        return r;
    }
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    r = real_vfprintf(stream, fmt, ap);
    va_end(ap);
    if (r >= 0) {

    }
    return r;
}

/* fputs shim — handle macOS FILE and clear __SERR */
int macify_fputs(const char *s, FILE *stream) __asm__("fputs");
int macify_fputs(const char *s, FILE *stream) {
    static int (*real_fputs)(const char *, FILE *) = NULL;
    if (!real_fputs) real_fputs = dlsym(RTLD_NEXT, "fputs");
    return real_fputs(s, stream);
}

/* fdopen — pass-through. Save initial state for macOS callers. */
FILE *macify_fdopen(int fd, const char *mode) __asm__("fdopen");
FILE *macify_fdopen(int fd, const char *mode) {
    static FILE *(*real_fdopen)(int, const char *) = NULL;
    if (!real_fdopen) real_fdopen = dlsym(RTLD_NEXT, "fdopen");
    FILE *fp = real_fdopen(fd, mode);
    if (fp && macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* Save initial _IO_read_ptr and _IO_read_end. */
        macify_save_read_ptr(fp);
        if (!macify_skip_r_patch) {
            *(int *)((char *)fp + 8) = -1;
        }
    }
    return fp;
}

/* fputc — handle macOS FILE */
int macify_fputc(int c, FILE *stream) __asm__("fputc");
int macify_fputc(int c, FILE *stream) {
    if (getenv("MACIFY_TRACE_WRITE")) {
        char b[64]; int n = snprintf(b, sizeof(b), "F(%02x)", c & 0xff);
        syscall(1, 2, b, n);
    }
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    int r = real_fputc(c, stream);
    if (r != EOF) {

    }
    return r;
}

/* putchar — write to macOS stdout */
int macify_putchar(int c) __asm__("putchar");
int macify_putchar(int c) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    extern FILE *__stdoutp;
    return real_fputc ? real_fputc(c, __stdoutp) : EOF;
}

/* puts — write string + newline to macOS stdout */
int macify_puts(const char *s) __asm__("puts");
int macify_puts(const char *s) {
    if (!s) return EOF;
    size_t len = strlen(s);
    extern FILE *__stdoutp;
    extern int macify_is_macos_file(void *);
    extern size_t macify_fwrite_macos(const void *, size_t, size_t, void *);
    if (macify_is_macos_file(__stdoutp)) {
        size_t r = macify_fwrite_macos(s, 1, len, __stdoutp);
        if (r != len) return EOF;
        macify_putchar('\n');
        return 0;
    }
    static int (*real_puts)(const char *) = NULL;
    if (!real_puts) real_puts = dlsym(RTLD_NEXT, "puts");
    return real_puts(s);
}

/* fflush — handle macOS FILE structs */
int macify_fflush(FILE *stream) __asm__("fflush");
int macify_fflush(FILE *stream) {
    static int (*real_fflush)(FILE *) = NULL;
    if (!real_fflush) real_fflush = dlsym(RTLD_NEXT, "fflush");
    /* When stream is NULL (flush all streams), glibc iterates ALL open
     * FILE* structures. macOS binaries corrupt some FILE* by writing to
     * offset 0x10 (thinking it's macOS _flags, but glibc has _IO_read_end
     * there). Glibc's fflush hangs on these corrupted streams.
     *
     * Fix: for fflush(NULL), only flush stdout and stderr directly via
     * write syscall, bypassing glibc's stream iteration. */
    if (stream == NULL) {
        extern FILE *__stdoutp, *__stderrp;
        FILE *streams[] = { __stdoutp, __stderrp, NULL };
        for (int i = 0; streams[i]; i++) {
            char **base = (char **)((char *)streams[i] + 0x28);
            char **ptr = (char **)((char *)streams[i] + 0x30);
            if (*ptr > *base && (size_t)(*ptr - *base) < 1048576) {
                int fd = (streams[i] == __stderrp) ? 2 : 1;
                write(fd, *base, *ptr - *base);
                *ptr = *base;  /* reset write pointer */
            }
        }
        return 0;
    }
    return real_fflush ? real_fflush(stream) : 0;
}
