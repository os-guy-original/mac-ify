/* macos_stdio.c — macOS-compatible FILE struct implementation
 *
 * macOS binaries use inlined putc/putchar macros that access the FILE
 * struct directly using macOS's layout:
 *   offset 0:  unsigned char *_p   (current position in buffer)
 *   offset 8:  int _r              (read space left)
 *   offset 12: int _w              (write space left)
 *   offset 16: short _flags
 *   offset 18: short _file         (file descriptor)
 *   offset 20: unsigned char *_bf._base (buffer start)
 *   offset 28: int _bf._size       (buffer size)
 *   offset 32: int _lbfsize        (line buffer size)
 *
 * glibc's FILE has a completely different layout:
 *   offset 0:  int _flags (0xfbad2084)
 *   offset 8:  char *_IO_read_ptr
 *   ...
 *
 * When bash's putc macro does *(_p)++ = c, it writes to the address
 * stored at offset 0 of glibc's FILE (which is _flags = 0xfbad2084),
 * not to a real buffer. The data is lost.
 *
 * Fix: provide macOS-format FILE structs for stdout/stderr/stdin.
 * The putc macro writes to our buffer. When the buffer is full,
 * __swbuf is called to flush it.
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

/* macOS FILE struct (only fields used by putc/getc macros) */
struct macos_sFILE {
    unsigned char *_p;          /* 0:  current position in buffer */
    int _r;                     /* 8:  read space left */
    int _w;                     /* 12: write space left */
    short _flags;               /* 16: flags */
    short _file;                /* 18: file descriptor */
    struct {
        unsigned char *_base;   /* 20: buffer start */
        int _size;              /* 28: buffer size */
    } _bf;
    int _lbfsize;               /* 32: line buffer size */
    char _pad[116];             /* pad to ~152 bytes */
};

#define MACOS_BUFSIZ 4096
static unsigned char macos_stdout_buf[MACOS_BUFSIZ];
static unsigned char macos_stderr_buf[MACOS_BUFSIZ];
static unsigned char macos_stdin_buf[MACOS_BUFSIZ];

static struct macos_sFILE macos_stdout = {
    ._p = macos_stdout_buf,
    ._r = 0,
    ._w = MACOS_BUFSIZ - 1,
    ._flags = MACOS___SWR | MACOS___SLBF,
    ._file = 1,
    ._bf = { ._base = macos_stdout_buf, ._size = MACOS_BUFSIZ },
    ._lbfsize = -1,
};

static struct macos_sFILE macos_stderr = {
    ._p = macos_stderr_buf,
    ._r = 0,
    ._w = MACOS_BUFSIZ - 1,
    ._flags = MACOS___SWR | MACOS___SNBF,
    ._file = 2,
    ._bf = { ._base = macos_stderr_buf, ._size = MACOS_BUFSIZ },
    ._lbfsize = 0,
};

static struct macos_sFILE macos_stdin = {
    ._p = macos_stdin_buf,
    ._r = 0,
    ._w = 0,
    ._flags = MACOS___SRD,
    ._file = 0,
    ._bf = { ._base = macos_stdin_buf, ._size = MACOS_BUFSIZ },
    ._lbfsize = 0,
};

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
    return 0;
}

/* Flush all macOS FILEs (called from fflush(NULL) and exit()) */
void macify_flush_macos_files(void) {
    macos_flush(&macos_stdout);
    macos_flush(&macos_stderr);
}

/* __swbuf is implemented in io/process.c — it handles both glibc FILE
 * and macOS FILE (via macify_is_macos_file check). */

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
        extern int __swbuf(int, void *);
        return __swbuf(c, (void *)f);
    }
    *f->_p++ = (unsigned char)c;
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

/* Initialize macOS FILE structs and set __stdoutp/__stderrp/__stdinp.
 * Called from the shim constructor. */
void macify_init_macos_stdio(void) {
    extern FILE *__stdoutp, *__stdinp, *__stderrp;
    __stdoutp = (FILE *)(void *)&macos_stdout;
    __stderrp = (FILE *)(void *)&macos_stderr;
    __stdinp = (FILE *)(void *)&macos_stdin;
}

/* Switch to macOS FILE structs for stdout/stderr.
 * Called by the macify loader after it detects the binary uses inlined
 * putc macros (text section > 100KB). This replaces glibc's FILE with
 * our macOS-format FILE, so the putc macro writes to a real buffer. */
void macify_use_macos_stdio(void) {
    extern FILE *__stdoutp, *__stderrp;
    /* Flush glibc's buffers using raw syscall to avoid glibc's FILE
     * validation (which would fail after we switch __stdoutp). */
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
    /* Note: __stdinp stays as glibc's stdin for now — read support
     * for macOS FILE is not yet implemented. */
}
