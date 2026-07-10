/* macos_stdio.c — macOS-compatible FILE struct implementation
 *
 * Provides macOS-format FILE structs for stdout/stderr/stdin so that
 * inlined putc/putchar macros write to a real buffer instead of
 * glibc's _flags field.
 *
 * The struct must be dual-layout compatible: macOS fields at macOS
 * offsets AND glibc fields at glibc offsets must both be valid.
 *
 * macOS FILE layout (struct __sFILE, ~152 bytes):
 *   0x00: _p (unsigned char*)
 *   0x08: _r (int)
 *   0x0c: _w (int)
 *   0x10: _flags (short)
 *   0x12: _file (short)
 *   0x14: _bf._base (unsigned char*)
 *   0x1c: _bf._size (int)
 *   0x20: _lbfsize (int)
 *   0x24: _cookie (void*)
 *   0x2c: _read (function pointer)
 *   0x34: _write (function pointer)
 *   0x3c: _seek (function pointer)
 *   0x44: _close (function pointer)
 *
 * glibc FILE layout:
 *   0x00: _flags (int)
 *   0x08: _IO_read_ptr (char*)
 *   0x10: _IO_read_end (char*)
 *   0x18: _IO_read_base (char*)
 *   0x20: _IO_write_base (char*)
 *   0x28: _IO_write_ptr (char*)
 *   0x30: _IO_write_end (char*)
 *   0x38: _IO_buf_base (char*)
 *   0x40: _IO_buf_end (char*)
 *
 * Conflict analysis:
 *   0x20: macOS _lbfsize (int) vs glibc _IO_write_base (char*) low 4 bytes
 *   0x24: macOS _cookie (void*) low vs glibc _IO_write_base high 4 bytes
 *   0x28: macOS _cookie high vs glibc _IO_write_ptr (char*) low 4 bytes
 *   0x2c: macOS _read (fn ptr) vs glibc _IO_write_ptr high 4 bytes
 *
 * Solution: use a union-like approach where:
 *   - _lbfsize + _cookie form glibc _IO_write_base (set to buffer start)
 *   - _read starts at 0x2c, which overlaps glibc _IO_write_ptr high bytes
 *   - _write at 0x34, _seek at 0x3c, _close at 0x44 are in glibc's
 *     _IO_buf_base/_IO_buf_end area — must be valid function pointers
 */

#include "../shim.h"
#include <unistd.h>
#include <string.h>

/* macOS FILE flags */
#define MACOS___SWR    0x0008
#define MACOS___SRD    0x0004
#define MACOS___SLBF   0x0100
#define MACOS___SNBF   0x0002
#define MACOS___SEOF   0x0020
#define MACOS___SERR   0x0040

/* Function pointer types for macOS FILE */
typedef int (*macos_read_fn)(void *, char *, int);
typedef int (*macos_write_fn)(void *, const char *, int);
typedef long long (*macos_seek_fn)(void *, long long, int);
typedef int (*macos_close_fn)(void *);

/* macOS FILE struct with dual-layout compatibility */
struct macos_sFILE {
    unsigned char *_p;          /* 0x00: current position in buffer */
    int _r;                     /* 0x08: read space left */
    int _w;                     /* 0x0c: write space left */
    short _flags;               /* 0x10: flags */
    short _file;                /* 0x12: file descriptor */
    struct {
        unsigned char *_base;   /* 0x14: buffer start */
        int _size;              /* 0x1c: buffer size */
    } _bf;
    /* 0x20: macOS _lbfsize (int) + macOS _cookie low (int)
     *       = glibc _IO_write_base (char*) — set to buffer start */
    union {
        struct { int _lbfsize; int _cookie_lo; } macos;
        unsigned char *_glibc_write_base;
    } u20;
    /* 0x28: macOS _cookie high (int) + macOS _read low (int)
     *       = glibc _IO_write_ptr (char*) — set to _p (current pos) */
    union {
        struct { int _cookie_hi; int _read_lo; } macos;
        unsigned char *_glibc_write_ptr;
    } u28;
    /* 0x30: macOS _read high (int) + macOS _write low (int)
     *       = glibc _IO_write_end (char*) — set to buffer end */
    union {
        struct { int _read_hi; int _write_lo; } macos;
        unsigned char *_glibc_write_end;
    } u30;
    /* 0x38: macOS _write high (int) + macOS _seek low (int)
     *       = glibc _IO_buf_base (char*) — set to buffer start */
    union {
        struct { int _write_hi; int _seek_lo; } macos;
        unsigned char *_glibc_buf_base;
    } u38;
    /* 0x40: macOS _seek high (int) + macOS _close low (int)
     *       = glibc _IO_buf_end (char*) — set to buffer end */
    union {
        struct { int _seek_hi; int _close_lo; } macos;
        unsigned char *_glibc_buf_end;
    } u40;
    /* 0x48: macOS _close high (int) + padding */
    int _close_hi;              /* 0x48 */
    char _pad[96];              /* 0x4c: pad to ~152 bytes */
};

#define MACOS_BUFSIZ 4096
static unsigned char macos_stdout_buf[MACOS_BUFSIZ];
static unsigned char macos_stderr_buf[MACOS_BUFSIZ];
static unsigned char macos_stdin_buf[MACOS_BUFSIZ];

/* Forward declarations */
static int macos_file_read(void *cookie, char *buf, int len);
static int macos_file_write(void *cookie, const char *buf, int len);
static long long macos_file_seek(void *cookie, long long off, int whence);
static int macos_file_close(void *cookie);

/* Helper to set function pointer in union at the right offset */
static void set_fn_ptr(struct macos_sFILE *f, int offset, void *fn) {
    memcpy((char *)f + offset, &fn, sizeof(void *));
}

static void init_macos_file(struct macos_sFILE *f, unsigned char *buf, int bufsiz,
                            short flags, short fd) {
    memset(f, 0, sizeof(*f));
    f->_p = buf;
    f->_r = 0;
    f->_w = bufsiz - 1;
    f->_flags = flags;
    f->_file = fd;
    f->_bf._base = buf;
    f->_bf._size = bufsiz;
    /* glibc _IO_write_base (0x20) = buffer start */
    f->u20._glibc_write_base = buf;
    /* glibc _IO_write_ptr (0x28) = buffer start (no data yet) */
    f->u28._glibc_write_ptr = buf;
    /* glibc _IO_write_end (0x30) = buffer end */
    f->u30._glibc_write_end = buf + bufsiz;
    /* glibc _IO_buf_base (0x38) = buffer start */
    f->u38._glibc_buf_base = buf;
    /* glibc _IO_buf_end (0x40) = buffer end */
    f->u40._glibc_buf_end = buf + bufsiz;
    /* macOS function pointers at 0x2c, 0x34, 0x3c, 0x44 */
    set_fn_ptr(f, 0x2c, (void *)macos_file_read);
    set_fn_ptr(f, 0x34, (void *)macos_file_write);
    set_fn_ptr(f, 0x3c, (void *)macos_file_seek);
    set_fn_ptr(f, 0x44, (void *)macos_file_close);
}

static struct macos_sFILE macos_stdout;
static struct macos_sFILE macos_stderr;
static struct macos_sFILE macos_stdin;

/* macOS FILE read/write/seek/close implementations */
static int macos_file_read(void *cookie, char *buf, int len) {
    struct macos_sFILE *f = (struct macos_sFILE *)cookie;
    if (!f) return -1;
    return (int)read(f->_file, buf, len);
}

static int macos_file_write(void *cookie, const char *buf, int len) {
    struct macos_sFILE *f = (struct macos_sFILE *)cookie;
    if (!f) return -1;
    return (int)write(f->_file, buf, len);
}

static long long macos_file_seek(void *cookie, long long off, int whence) {
    struct macos_sFILE *f = (struct macos_sFILE *)cookie;
    if (!f) return -1;
    return (long long)lseek(f->_file, off, whence);
}

static int macos_file_close(void *cookie) {
    struct macos_sFILE *f = (struct macos_sFILE *)cookie;
    if (!f) return -1;
    return close(f->_file);
}

/* Check if a FILE* is one of our macOS FILE structs */
int macify_is_macos_file(void *fp) {
    return fp == (void *)&macos_stdout ||
           fp == (void *)&macos_stderr ||
           fp == (void *)&macos_stdin;
}

/* Flush a macOS FILE's write buffer */
static int macos_flush(struct macos_sFILE *fp) {
    if (!fp) return 0;
    if (!(fp->_flags & MACOS___SWR)) return 0;
    int len = (int)(fp->_p - fp->_bf._base);
    if (len > 0) {
        ssize_t r = write(fp->_file, fp->_bf._base, len);
        (void)r;
    }
    fp->_p = fp->_bf._base;
    fp->_w = fp->_bf._size - 1;
    /* Keep glibc _IO_write_ptr in sync */
    fp->u28._glibc_write_ptr = fp->_p;
    return 0;
}

/* Flush all macOS FILEs (called from fflush(NULL) and exit()) */
void macify_flush_macos_files(void) {
    macos_flush(&macos_stdout);
    macos_flush(&macos_stderr);
}

/* Write to a macOS FILE. Returns number of bytes written. */
size_t macify_fwrite_macos(const void *ptr, size_t size, size_t nmemb, void *fp) {
    if (!macify_is_macos_file(fp)) return 0;
    struct macos_sFILE *f = (struct macos_sFILE *)fp;
    size_t total = size * nmemb;
    const char *p = (const char *)ptr;

    /* Flush existing buffer contents first */
    macos_flush(f);

    /* Write directly via write() */
    if (total > 0) {
        ssize_t r = write(f->_file, p, total);
        (void)r;
    }
    return nmemb;
}

/* Fputc to a macOS FILE */
int macify_fputc_macos(int c, void *fp) {
    if (!macify_is_macos_file(fp)) return EOF;
    struct macos_sFILE *f = (struct macos_sFILE *)fp;
    if (--f->_w < 0) {
        /* Buffer full — flush and retry */
        macos_flush(f);
        *f->_p++ = (unsigned char)c;
        f->_w--;
    } else {
        *f->_p++ = (unsigned char)c;
    }
    /* Keep glibc _IO_write_ptr in sync */
    f->u28._glibc_write_ptr = f->_p;
    /* Line-buffered: flush on newline */
    if ((f->_flags & MACOS___SLBF) && c == '\n') {
        macos_flush(f);
    }
    return (unsigned char)c;
}

/* fflush for macOS FILE */
int macify_fflush_macos(void *fp) {
    if (fp && macify_is_macos_file(fp)) {
        return macos_flush((struct macos_sFILE *)fp);
    }
    if (fp == NULL) {
        macify_flush_macos_files();
    }
    return 0;
}

/* Initialize macOS FILE structs and set __stdoutp/__stderrp/__stdinp. */
void macify_init_macos_stdio(void) {
    init_macos_file(&macos_stdout, macos_stdout_buf, MACOS_BUFSIZ,
                    MACOS___SWR | MACOS___SLBF, 1);
    init_macos_file(&macos_stderr, macos_stderr_buf, MACOS_BUFSIZ,
                    MACOS___SWR | MACOS___SNBF, 2);
    init_macos_file(&macos_stdin, macos_stdin_buf, MACOS_BUFSIZ,
                    MACOS___SRD, 0);
    extern FILE *__stdoutp, *__stdinp, *__stderrp;
    __stdoutp = (FILE *)(void *)&macos_stdout;
    __stderrp = (FILE *)(void *)&macos_stderr;
    __stdinp = (FILE *)(void *)&macos_stdin;
}

/* Switch to macOS FILE structs for stdout/stderr. */
void macify_use_macos_stdio(void) {
    /* Initialize macOS FILE structs if not already done */
    static int initialized = 0;
    if (!initialized) {
        init_macos_file(&macos_stdout, macos_stdout_buf, MACOS_BUFSIZ,
                        MACOS___SWR | MACOS___SLBF, 1);
        init_macos_file(&macos_stderr, macos_stderr_buf, MACOS_BUFSIZ,
                        MACOS___SWR | MACOS___SNBF, 2);
        init_macos_file(&macos_stdin, macos_stdin_buf, MACOS_BUFSIZ,
                        MACOS___SRD, 0);
        initialized = 1;
    }
    extern FILE *__stdoutp, *__stderrp;
    /* Flush glibc's buffers using raw syscall */
    extern FILE *stdout, *stderr;
    {
        char **base = (char **)((char *)stdout + 0x28);
        char **ptr = (char **)((char *)stdout + 0x30);
        if (*ptr > *base && (size_t)(*ptr - *base) < 1048576) {
            syscall(1, 1, *base, *ptr - *base);
            *ptr = *base;
        }
    }
    {
        char **base = (char **)((char *)stderr + 0x28);
        char **ptr = (char **)((char *)stderr + 0x30);
        if (*ptr > *base && (size_t)(*ptr - *base) < 1048576) {
            syscall(1, 2, *base, *ptr - *base);
            *ptr = *base;
        }
    }
    /* Switch to macOS FILE structs */
    __stdoutp = (FILE *)(void *)&macos_stdout;
    __stderrp = (FILE *)(void *)&macos_stderr;
}

/* __srget — read one character from a macOS FILE */
int macify___srget_macos(void *fp) {
    if (!macify_is_macos_file(fp)) return EOF;
    struct macos_sFILE *f = (struct macos_sFILE *)fp;
    unsigned char c;
    ssize_t r = read(f->_file, &c, 1);
    if (r <= 0) {
        f->_flags |= MACOS___SEOF;
        return EOF;
    }
    f->_r = 0;
    f->_p = f->_bf._base;
    return c;
}
