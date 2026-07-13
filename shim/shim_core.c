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

/* ── termcap function wrappers ──────────────────────────────────
 * macOS's ncurses exports tgetent/tgoto/tputs etc. and the termcap
 * variables BC, PC, UP. Linux's ncurses does NOT export BC/PC/UP,
 * and on some distros (Artix) doesn't even export tgetent etc.
 *
 * We export BC/PC/UP as globals and provide tgetent/tgetstr/etc.
 * wrappers that DELEGATE to the real implementations from libtinfo
 * or libncursesw if available, falling back to stubs if not.
 *
 * After calling the real tgetent, we sync BC/PC/UP from the real
 * library's internal variables (via dlsym) so readline can use them. */

/* Termcap global variables — exported for readline's GOT */

/* Helper: get the real termcap functions.
 * CRITICAL: Try macOS libncurses (Mach-O dylib) FIRST, then Linux libtinfo.
 * macOS libedit (readline) was compiled against macOS libncurses and expects
 * its internal buffer management. Using Linux libtinfo's tgetent causes a
 * buffer overflow that crashes bash. */
static int (*real_tgetent)(char *, const char *) = NULL;
static int (*real_tgetflag)(const char *) = NULL;
static int (*real_tgetnum)(const char *) = NULL;
static char *(*real_tgetstr)(const char *, char **) = NULL;
static char *(*real_tgoto)(const char *, int, int) = NULL;
static int (*real_tputs)(const char *, int, int (*)(int)) = NULL;

static void init_real_termcap(void) {
    if (real_tgetent) return;  /* already initialized */
    /* Try macOS libncurses (Mach-O dylib) first.
     * macho_dylib_lookup is provided by the macify loader. */
    extern void *macho_dylib_lookup(const char *);
    real_tgetent  = macho_dylib_lookup("tgetent");
    real_tgetflag = macho_dylib_lookup("tgetflag");
    real_tgetnum  = macho_dylib_lookup("tgetnum");
    real_tgetstr  = macho_dylib_lookup("tgetstr");
    real_tgoto    = macho_dylib_lookup("tgoto");
    real_tputs    = macho_dylib_lookup("tputs");
    if (real_tgetent) return;  /* macOS libncurses found */

    /* Fallback: Linux libtinfo/libncursesw */
    void *h = dlopen("libtinfo.so.6", RTLD_NOW);
    if (!h) h = dlopen("libtinfo.so.5", RTLD_NOW);
    if (!h) h = dlopen("libncursesw.so.6", RTLD_NOW);
    if (!h) h = dlopen("libncurses.so.6", RTLD_NOW);
    if (!h) return;
    real_tgetent  = dlsym(h, "tgetent");
    real_tgetflag = dlsym(h, "tgetflag");
    real_tgetnum  = dlsym(h, "tgetnum");
    real_tgetstr  = dlsym(h, "tgetstr");
    real_tgoto    = dlsym(h, "tgoto");
    real_tputs    = dlsym(h, "tputs");
}

int tgetent(char *buf, const char *name) {
    init_real_termcap();
    if (getenv("MACIFY_TRACE_TERMCAP")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: shim tgetent(buf=%p, name=\"%s\") called, real_tgetent=%p\n",
            buf, name ? name : "(null)", real_tgetent);
        (void)write(2, b, n);
    }
    if (real_tgetent) {
        /* Use a LARGE internal buffer to prevent overflow.
         * macOS libedit (readline) typically provides a 1024-byte buffer
         * for tgetent. But macOS libncurses's tgetent may write more
         * (up to 4096 bytes for complex terminals like xterm-256color).
         * This overflow corrupts readline's stack, causing a crash at
         * &_terminating_signal on the next readline call.
         *
         * Fix: call real_tgetent with a large internal buffer, then
         * copy only the first 1024 bytes to the caller's buffer. */
        static char large_buf[8192];
        int r = real_tgetent(large_buf, name);
        if (buf) {
            /* Copy to caller's buffer (truncate to 1024 bytes) */
            memcpy(buf, large_buf, 1024);
        }
        if (getenv("MACIFY_TRACE_TERMCAP")) {
            char b[128]; int n = snprintf(b, sizeof(b),
                "macify: real_tgetent returned %d (used 8192-byte buffer)\n", r);
            (void)write(2, b, n);
        }
        /* Sync BC/PC/UP from macOS libncurses's globals (if available),
         * falling back to Linux libtinfo. */
        extern void *macho_dylib_lookup(const char *);
        char **pBC = macho_dylib_lookup("BC");
        char  *pPC = macho_dylib_lookup("PC");
        char **pUP = macho_dylib_lookup("UP");
        if (!pBC || !pPC || !pUP) {
            /* Fallback: Linux libtinfo */
            void *h = dlopen("libtinfo.so.6", RTLD_NOW);
            if (!h) h = dlopen("libncursesw.so.6", RTLD_NOW);
            if (h) {
                if (!pBC) pBC = dlsym(h, "BC");
                if (!pPC) pPC = dlsym(h, "PC");
                if (!pUP) pUP = dlsym(h, "UP");
            }
        }
        if (pBC) BC = *pBC;
        if (pPC) PC = *pPC;
        if (pUP) UP = *pUP;
        return r;
    }
    /* Fallback: pretend we found an xterm-compatible terminal.
     * This is safe because virtually all modern terminals (including
     * Linux console, xterm, gnome-terminal, kitty, alacritty) support
     * ANSI escape sequences. */
    if (buf) buf[0] = '\0';
    return 1;
}

/* Minimal xterm-compatible terminal capability strings.
 * Used as fallback when real termcap is unavailable. */
static char *tgetstr_fallback(const char *id) {
    /* Key sequences */
    if (strcmp(id, "ku") == 0) return "\033[A";  /* up */
    if (strcmp(id, "kd") == 0) return "\033[B";  /* down */
    if (strcmp(id, "kr") == 0) return "\033[C";  /* right */
    if (strcmp(id, "kl") == 0) return "\033[D";  /* left */
    if (strcmp(id, "kh") == 0) return "\033[H";  /* home */
    if (strcmp(id, "kH") == 0) return "\033[F";  /* end */
    if (strcmp(id, "kD") == 0) return "\033[3~"; /* delete */
    if (strcmp(id, "kI") == 0) return "\033[2~"; /* insert */
    if (strcmp(id, "k1") == 0) return "\033OP";  /* F1 */
    if (strcmp(id, "k2") == 0) return "\033OQ";  /* F2 */
    if (strcmp(id, "k3") == 0) return "\033OR";  /* F3 */
    if (strcmp(id, "k4") == 0) return "\033OS";  /* F4 */
    if (strcmp(id, "k5") == 0) return "\033[15~";/* F5 */
    /* Cursor movement */
    if (strcmp(id, "cr") == 0) return "\r";      /* carriage return */
    if (strcmp(id, "nl") == 0) return "\n";      /* newline */
    if (strcmp(id, "le") == 0) return "\b";      /* cursor left */
    if (strcmp(id, "nd") == 0) return "\033[C";  /* cursor right */
    if (strcmp(id, "up") == 0) return "\033[A";  /* cursor up */
    if (strcmp(id, "do") == 0) return "\033[B";  /* cursor down */
    if (strcmp(id, "ho") == 0) return "\033[H";  /* home */
    if (strcmp(id, "ce") == 0) return "\033[K";  /* clear to end of line */
    if (strcmp(id, "cd") == 0) return "\033[J";  /* clear to end of screen */
    if (strcmp(id, "cl") == 0) return "\033[2J\033[H"; /* clear screen */
    /* Misc */
    if (strcmp(id, "bc") == 0) return "\b";      /* backspace */
    if (strcmp(id, "bl") == 0) return "\a";      /* bell */
    if (strcmp(id, "md") == 0) return "\033[1m"; /* bold */
    if (strcmp(id, "me") == 0) return "\033[0m"; /* end attrs */
    if (strcmp(id, "so") == 0) return "\033[7m"; /* standout */
    if (strcmp(id, "se") == 0) return "\033[0m"; /* end standout */
    if (strcmp(id, "us") == 0) return "\033[4m"; /* underline */
    if (strcmp(id, "ue") == 0) return "\033[0m"; /* end underline */
    return NULL;
}

int tgetflag(const char *id) {
    init_real_termcap();
    if (real_tgetflag) return real_tgetflag(id);
    /* xterm-compatible flags */
    if (strcmp(id, "am") == 0) return 1;  /* auto right margin */
    if (strcmp(id, "xn") == 0) return 1;  /* newline ignored after wrap */
    return 0;
}
int tgetnum(const char *id) {
    init_real_termcap();
    if (real_tgetnum) return real_tgetnum(id);
    if (strcmp(id, "co") == 0) return 80;  /* columns */
    if (strcmp(id, "li") == 0) return 24;  /* lines */
    return -1;
}
char *tgetstr(const char *id, char **area) {
    init_real_termcap();
    if (real_tgetstr) return real_tgetstr(id, area);
    return tgetstr_fallback(id);
}
char *tgoto(const char *cap, int col, int row) {
    init_real_termcap();
    if (real_tgoto) return real_tgoto(cap, col, row);
    return (char *)cap;
}
int tputs(const char *str, int affcnt, int (*putc_fn)(int)) {
    init_real_termcap();
    if (real_tputs) return real_tputs(str, affcnt, putc_fn);
    /* Fallback: output string, skipping $<padding> delays */
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
