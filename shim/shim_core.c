#include "shim.h"

/* __TEXT range of the loaded macOS main image, set by the loader.
 * Used by network shim functions to decide whether to translate errno.
 * See the long comment in shim.h for details. */
uintptr_t macify_text_lo = 0;
uintptr_t macify_text_hi = 0;

void __macify_set_text_range(uint64_t lo, uint64_t hi) {
    macify_text_lo = (uintptr_t)lo;
    macify_text_hi = (uintptr_t)hi;
}

int macify_caller_is_macos_text(void *ret_addr) {
    /* If the range hasn't been initialized yet, return FALSE.
     * During early initialization (before g_macos_text_lo is set),
     * only macify's own code and glibc are running — NOT the macOS
     * binary. Returning FALSE ensures path/flag translation is NOT
     * applied to macify's own open/sigaction/stat calls. */
    if (macify_text_lo == 0 || macify_text_hi == 0) return 0;
    uintptr_t a = (uintptr_t)ret_addr;
    return (a >= macify_text_lo && a < macify_text_hi);
}

int *__errno(void) {
    return __errno_location();
}

/* Also provide _errno as some code calls it directly */
int *_errno(void) {
    return __errno_location();
}

/* _NSGetEnviron — returns pointer to the environ global.
 * 
 * macOS binaries access environment via _NSGetEnviron() which returns
 * char ***. On Linux, environ is a direct global.
 */

extern char **environ;

char ***_NSGetEnviron(void) {
    return &environ;
}

/* ___progname — program name global.
 * 
 * macOS has a global ___progname (three underscores) that holds the
 * program name. Many macOS binaries reference it.
 */

char *___progname = "macify-app";

/* __progname (two underscores) is also common */
char *__progname = "macify-app";

/* __stack_chk_guard — stack canary value global.
 *
 * On macOS, __stack_chk_guard is a global variable that holds the stack
 * canary. We sync it from glibc's TLS canary (%fs:0x28) at startup for
 * proper randomization. */
uintptr_t __stack_chk_guard = 0;

uintptr_t _STACK_CHK_GUARD = 0;

/* Sync canary from glibc's TLS at constructor time */
__attribute__((constructor))
static void init_stack_chk_guard(void) {
    uintptr_t canary;
    __asm__ volatile("movq %%fs:0x28, %0" : "=r"(canary));
    if (canary == 0) canary = 0x1234567890ABCDEFu;  /* fallback */
    __stack_chk_guard = canary;
    _STACK_CHK_GUARD = canary;
}

void __stack_chk_fail(void) {
    /* Use write() not fprintf() — async-signal-safe */
    const char msg[] = "macify: stack smashing detected\n";
    (void)write(2, msg, sizeof(msg) - 1);
    abort();
}

/* _dyld_image_count / _dyld_get_image_* — dynamic loader introspection.
 * 
 * macOS apps can query the dynamic loader for loaded images. We provide
 * minimal stubs that report just the main executable.
 */

static const char *__macify_image_name = "/macify/app.bin";

uint32_t _dyld_image_count(void) {
    return 1;  /* just the main executable */
}

const char *_dyld_get_image_name(uint32_t image_index) {
    if (image_index == 0) return __macify_image_name;
    return NULL;
}

/* The actual load base of the main image, set by the loader.
 * _dyld_get_image_header(0) must return this (the slid address).
 *
 * NOTE: deliberately NOT `static` — shim_pthread.c references this
 * via `extern` for the MACIFY_SSL_DEBUG ret_global reader. With
 * `static`, the symbol is local to this TU and dlopen(RTLD_NOW)
 * fails at startup with "undefined symbol: macify_image_header",
 * which prevents the entire shim from loading (and curl dies before
 * even running main, with the misleading "failed to load shim/libc"
 * message from the loader). */
uint64_t macify_image_header = 0;

void __macify_set_image_header(uint64_t header) {
    macify_image_header = header;
}

uint64_t _dyld_get_image_header(uint64_t image_index) {
    if (image_index == 0) return macify_image_header;
    return 0;
}

int64_t _dyld_get_image_vmaddr_slide(uint64_t image_index) {
    /* Return the slide. The loader sets macify_image_header. */
    (void)image_index;
    return 0;  /* slide is already included in macify_image_header */
}

uint64_t _dyld_get_image_slide(uint64_t image_index) {
    return _dyld_get_image_vmaddr_slide(image_index);
}
int *__error(void) {
    return __errno_location();
}

/* Linux → macOS errno translation table.
 *
 * Many network-related errno values differ between macOS and Linux.
 * When our shim functions (connect, send, recv, etc.) return -1, glibc
 * sets the Linux errno. The macOS binary reads errno via __error() and
 * compares it to macOS errno constants compiled into the binary.
 *
 * Example: macOS EINPROGRESS=36, Linux EINPROGRESS=115. After a
 * non-blocking connect, the macOS binary checks `if (errno != 36)`
 * and treats EINPROGRESS as a real failure if it sees 115.
 *
 * Solution: translate Linux errno values back to macOS errno values
 * before returning from shim functions on the error path.
 *
 * The macOS errno layout matches Linux up to 34 (ERANGE). After that:
 *   macOS 35 = EAGAIN/EWOULDBLOCK  (Linux 11)
 *   macOS 36 = EINPROGRESS         (Linux 115)
 *   macOS 37 = EALREADY            (Linux 114)
 *   macOS 38 = ENOTSOCK            (Linux 88)
 *   macOS 39 = EDESTADDRREQ        (Linux 89)
 *   macOS 40 = EMSGSIZE            (Linux 90)
 *   macOS 41 = EPROTOTYPE          (Linux 91)
 *   macOS 42 = ENOPROTOOPT         (Linux 92)
 *   macOS 43 = EPROTONOSUPPORT     (Linux 93)
 *   macOS 44 = ESOCKTNOSUPPORT     (Linux 94)
 *   macOS 45 = EOPNOTSUPP          (Linux 95)
 *   macOS 46 = EPFNOSUPPORT        (Linux 96)
 *   macOS 47 = EAFNOSUPPORT        (Linux 97)
 *   macOS 48 = EADDRINUSE          (Linux 98)
 *   macOS 49 = EADDRNOTAVAIL       (Linux 99)
 *   macOS 50 = ENETDOWN            (Linux 100)
 *   macOS 51 = ENETUNREACH         (Linux 101)
 *   macOS 52 = ENETRESET           (Linux 102)
 *   macOS 53 = ECONNABORTED        (Linux 103)
 *   macOS 54 = ECONNRESET          (Linux 104)
 *   macOS 55 = ENOBUFS             (Linux 105)
 *   macOS 56 = EISCONN             (Linux 106)
 *   macOS 57 = ENOTCONN            (Linux 107)
 *   macOS 58 = ESHUTDOWN           (Linux 108)
 *   macOS 59 = ETOOMANYREFS        (Linux 109)
 *   macOS 60 = ETIMEDOUT           (Linux 110)
 *   macOS 61 = ECONNREFUSED        (Linux 111)
 *   macOS 62 = ELOOP               (Linux 40)
 *   macOS 63 = ENAMETOOLONG        (Linux 36)
 *   macOS 64 = EHOSTDOWN           (Linux 112)
 *   macOS 65 = EHOSTUNREACH        (Linux 113)
 *   macOS 66 = ENOTEMPTY           (Linux 39)
 *   macOS 77 = ENOLCK              (Linux 37)
 *   macOS 78 = ENOSYS              (Linux 38)
 */
int macify_linux_to_macos_errno(int linux_errno) {
    switch (linux_errno) {
        case 11:  return 35;   /* EAGAIN/EWOULDBLOCK */
        case 36:  return 63;   /* ENAMETOOLONG */
        case 37:  return 77;   /* ENOLCK */
        case 38:  return 78;   /* ENOSYS */
        case 39:  return 66;   /* ENOTEMPTY */
        case 40:  return 62;   /* ELOOP */
        case 88:  return 38;   /* ENOTSOCK */
        case 89:  return 39;   /* EDESTADDRREQ */
        case 90:  return 40;   /* EMSGSIZE */
        case 91:  return 41;   /* EPROTOTYPE */
        case 92:  return 42;   /* ENOPROTOOPT */
        case 93:  return 43;   /* EPROTONOSUPPORT */
        case 94:  return 44;   /* ESOCKTNOSUPPORT */
        case 95:  return 45;   /* EOPNOTSUPP */
        case 96:  return 46;   /* EPFNOSUPPORT */
        case 97:  return 47;   /* EAFNOSUPPORT */
        case 98:  return 48;   /* EADDRINUSE */
        case 99:  return 49;   /* EADDRNOTAVAIL */
        case 100: return 50;   /* ENETDOWN */
        case 101: return 51;   /* ENETUNREACH */
        case 102: return 52;   /* ENETRESET */
        case 103: return 53;   /* ECONNABORTED */
        case 104: return 54;   /* ECONNRESET */
        case 105: return 55;   /* ENOBUFS */
        case 106: return 56;   /* EISCONN */
        case 107: return 57;   /* ENOTCONN */
        case 108: return 58;   /* ESHUTDOWN */
        case 109: return 59;   /* ETOOMANYREFS */
        case 110: return 60;   /* ETIMEDOUT */
        case 111: return 61;   /* ECONNREFUSED */
        case 112: return 64;   /* EHOSTDOWN */
        case 113: return 65;   /* EHOSTUNREACH */
        case 114: return 37;   /* EALREADY */
        case 115: return 36;   /* EINPROGRESS */
        case 116: return 70;   /* ESTALE */
        default:   return linux_errno;  /* same on both, or unknown */
    }
}

/* ___stderrp / ___stdinp / ___stdoutp — macOS FILE pointers.
 * 
 * On macOS, stdin/stdout/stderr are accessed via these global
 * FILE* pointers. On Linux, they're `stdin`/`stdout`/`stderr`.
 * We provide the macOS-named globals pointing to the same FILEs.
 */

#include <stdio.h>

/* These are the actual FILE* values. The macOS binary reads these
 * pointers to get stdin/stdout/stderr. */


/* Provide the macOS-named globals. The binary has ___stdinp (3 underscores),
 * which after stripping 1 becomes __stdinp (2 underscores). So we define
 * C globals with 2 underscores, which export as __stdinp on Linux. */
FILE *__stderrp = NULL;
FILE *__stdinp = NULL;
FILE *__stdoutp = NULL;
/* __NSGetArgc / __NSGetArgv / __NSGetExecutablePath
 * 
 * macOS provides these functions to access argc, argv, and the
 * executable path. They return pointers to the actual data.
 */

static int __macify_argc = 0;
static char **__macify_argv = NULL;
static char __macify_exec_path[4096] = "/macify/app";

void __macify_set_args(int argc, char **argv, const char *exec_path) {
    __macify_argc = argc;
    __macify_argv = argv;
    if (exec_path) {
        strncpy(__macify_exec_path, exec_path, sizeof(__macify_exec_path) - 1);
    }
    /* Set __progname from argv[0] (basename). macOS binaries use getprogname()
     * to get the program name for error messages. */
    if (argv && argv[0]) {
        const char *slash = strrchr(argv[0], '/');
        const char *base = slash ? slash + 1 : argv[0];
        /* Update both __progname and ___progname */
        extern char *__progname, *___progname;
        static char progname_buf[256];
        strncpy(progname_buf, base, sizeof(progname_buf) - 1);
        progname_buf[sizeof(progname_buf) - 1] = '\0';
        __progname = progname_buf;
        ___progname = progname_buf;
    }
}

int *_NSGetArgc(void) {
    return &__macify_argc;
}

char ***_NSGetArgv(void) {
    return &__macify_argv;
}

int _NSGetExecutablePath(char *buf, uint32_t *bufsize) {
    if (!buf || !bufsize) return -1;
    size_t len = strlen(__macify_exec_path);
    if (*bufsize < len + 1) {
        *bufsize = len + 1;
        return -1;
    }
    memcpy(buf, __macify_exec_path, len + 1);
    *bufsize = len;
    return 0;
}

/* ── termcap global variables (BC, PC, UP) ──────────────────────
 * macOS's ncurses exports these as global variables that readline
 * references via GOT. Linux's ncurses does NOT export them — they're
 * internal. Without providing them, readline's GOT entries resolve
 * to NULL, causing crashes (rip=0x8) in interactive mode.
 *
 *   BC — char* : backspace cursor movement string
 *   PC — char  : padding character
 *   UP — char* : cursor up movement string
 *
 * These are normally set by tgetent() after reading the terminal entry.
 * We initialize them to safe defaults. tgetent (from libncursesw) will
 * set Linux's internal copies but NOT these — we intercept tgetent in
 * file.c to sync them. */
char *BC = (char *)"\b";   /* backspace */
char  PC = 0;              /* no padding */
char *UP = (char *)"\033[A"; /* ESC [ A = cursor up */

/* ── termcap function stubs ─────────────────────────────────────
 * Some Linux distros (Artix, Arch) don't have libtinfo as a separate
 * library, and libncursesw doesn't export tgetent/tgoto/tputs.
 * Without these, readline's GOT entries resolve to NULL, causing
 * rip=0x8 crash in interactive mode.
 *
 * We provide minimal stubs. tgetent returns 1 (success) to tell
 * readline the terminal entry was found. tgetstr returns NULL for
 * unknown capabilities (readline handles this). tgoto and tputs are
 * pass-throughs. */
int tgetent(char *buf, const char *name) {
    if (buf) buf[0] = '\0';
    return 1;  /* success: terminal entry found */
}
int tgetflag(const char *id) { return 0; }
int tgetnum(const char *id) { return -1; }
char *tgetstr(const char *id, char **area) { return NULL; }
char *tgoto(const char *cap, int col, int row) { return (char *)cap; }
int tputs(const char *str, int affcnt, int (*putc_fn)(int)) {
    if (!str) return 0;
    while (*str) {
        if (*str == '$' && str[1] == '<') {
            str += 2;
            while (*str && *str != '>') str++;
            if (*str) str++;
            continue;
        }
        if (putc_fn) putc_fn((unsigned char)*str);
        str++;
    }
    return 0;
}
