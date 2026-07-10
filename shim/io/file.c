/* file.c — file I/O: fcntl, strerror_r, stat/lstat/fstat, passwd,
 * realpath, readlink, getcwd, mkdir, isatty */
#include "io_internal.h"
#include <sys/stat.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <termios.h>

/* ── realpath ────────────────────────────────────────────────── */
char *macify_realpath(const char *path, char *resolved) __asm__("realpath");
char *macify_realpath(const char *path, char *resolved) {
    static char *(*real)(const char *, char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "realpath");
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return NULL; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    char *r = real(eff, resolved);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: realpath(\"%s\") = %s errno=%d\n",
            path ? path : "(null)", r ? r : "NULL", r ? 0 : errno);
        (void)write(2, b, n);
    }
    return r;
}

/* ── readlink ────────────────────────────────────────────────── */
ssize_t macify_readlink(const char *path, char *buf, size_t bufsiz) __asm__("readlink");
ssize_t macify_readlink(const char *path, char *buf, size_t bufsiz) {
    static ssize_t (*real)(const char *, char *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "readlink");
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    ssize_t r = real(eff, buf, bufsiz);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: readlink(\"%s\") = %zd errno=%d\n",
            path ? path : "(null)", r, r < 0 ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

/* ── getcwd ──────────────────────────────────────────────────── */
char *macify_getcwd(char *buf, size_t size) __asm__("getcwd");
char *macify_getcwd(char *buf, size_t size) {
    static char *(*real)(char *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getcwd");
    char *r = real(buf, size);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: getcwd() = %s\n", r ? r : "NULL");
        (void)write(2, b, n);
    }
    return r;
}

/* ── mkdir ───────────────────────────────────────────────────── */
int macify_mkdir(const char *path, mode_t mode) __asm__("mkdir");
int macify_mkdir(const char *path, mode_t mode) {
    static int (*real)(const char *, mode_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "mkdir");
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    int r = real(eff, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: mkdir(\"%s\", 0%o) = %d errno=%d\n",
            path ? path : "(null)", mode, r, r ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

/* ── isatty ──────────────────────────────────────────────────── */
int macify_isatty(int fd) __asm__("isatty");
int macify_isatty(int fd) {
    static int (*real)(int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "isatty");
    int r = real(fd);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[128]; int n = snprintf(b, sizeof(b),
            "macify: isatty(%d) = %d\n", fd, r);
        (void)write(2, b, n);
    }
    /* isatty returns 0 for non-terminals but glibc's isatty leaves
     * errno set to ENOTTY. Clear it so Rust doesn't read stale errno. */
    if (r == 0) errno = 0;
    return r;
}

/* ── fcntl ───────────────────────────────────────────────────── */

int fcntl(int fd, int cmd, ...) {
    LAZY_INIT_IO();
    /* Only translate for macOS callers. Linux libraries (libedit, glibc)
     * call fcntl with Linux constants — translating those corrupts data. */
    if (!macify_caller_is_macos_text(__builtin_return_address(0))) {
        va_list ap; va_start(ap, cmd);
        void *arg = va_arg(ap, void *); va_end(ap);
        return real_fcntl(fd, cmd, arg);
    }
    int linux_cmd = translate_fcntl_cmd(cmd);
    if (cmd == 1) return real_fcntl(fd, linux_cmd);
    if (cmd == 3) {
        int linux_fl = real_fcntl(fd, linux_cmd);
        if (linux_fl < 0) return linux_fl;
        unsigned int macos_fl = linux_fl & 0x3;
        if (linux_fl & LINUX_O_APPEND)    macos_fl |= MACOS_O_APPEND;
        if (linux_fl & LINUX_O_NONBLOCK)  macos_fl |= MACOS_O_NONBLOCK;
        if (linux_fl & LINUX_O_CREAT)     macos_fl |= MACOS_O_CREAT;
        if (linux_fl & LINUX_O_EXCL)      macos_fl |= MACOS_O_EXCL;
        if (linux_fl & LINUX_O_TRUNC)     macos_fl |= MACOS_O_TRUNC;
        if (linux_fl & LINUX_O_NOCTTY)    macos_fl |= MACOS_O_NOCTTY;
        if (linux_fl & LINUX_O_SYNC)      macos_fl |= MACOS_O_SYNC;
        if (linux_fl & LINUX_O_CLOEXEC)   macos_fl |= MACOS_O_CLOEXEC;
        if (linux_fl & LINUX_O_DIRECTORY) macos_fl |= MACOS_O_DIRECTORY;
        if (linux_fl & LINUX_O_NOFOLLOW)  macos_fl |= MACOS_O_NOFOLLOW;
        return (int)macos_fl;
    }
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (cmd == 4) {
        unsigned int macos_fl = (unsigned int)(long)arg;
        unsigned int linux_fl = translate_open_flags(macos_fl);
        return real_fcntl(fd, linux_cmd, (void *)(long)linux_fl);
    }
    if (cmd == 7 || cmd == 8 || cmd == 9) {
        struct macos_flock { int64_t l_start; int64_t l_len; int32_t l_pid; int16_t l_type; int16_t l_whence; };
        struct macos_flock *mf = (struct macos_flock *)arg;
        struct flock lf;
        memset(&lf, 0, sizeof(lf));
        switch (mf->l_type) {
            case 1: lf.l_type = F_RDLCK; break;
            case 2: lf.l_type = F_UNLCK; break;
            case 3: lf.l_type = F_WRLCK; break;
            default: lf.l_type = mf->l_type; break;
        }
        lf.l_whence = mf->l_whence;
        lf.l_start = mf->l_start;
        lf.l_len = mf->l_len;
        lf.l_pid = mf->l_pid;
        int ret = real_fcntl(fd, linux_cmd, &lf);
        if (cmd == 7 && ret >= 0) {
            switch (lf.l_type) {
                case F_RDLCK: mf->l_type = 1; break;
                case F_WRLCK: mf->l_type = 3; break;
                case F_UNLCK: mf->l_type = 2; break;
                default: mf->l_type = lf.l_type; break;
            }
            mf->l_whence = lf.l_whence;
            mf->l_start = lf.l_start;
            mf->l_len = lf.l_len;
            mf->l_pid = lf.l_pid;
        }
        return ret;
    }
    if (cmd >= 16 && cmd != 67) {
        switch (cmd) {
            case 16: return 0; case 17: return 0;
            case 48: return 0; case 50: errno = ENOTSUP; return -1;
            /* F_FULLFSYNC (51) and F_BARRIERFSYNC (55) on macOS force the
             * disk to flush its write cache. Linux has no direct equivalent,
             * but fsync() is the closest — it flushes kernel buffers and
             * asks the device to flush its cache. Without this, sqlite3
             * thinks its commits are durable when they may not be. */
            case 51: return fsync(fd);
            case 55: return fdatasync(fd);
            case 61: return 0; case 63: return 0; case 42: return 0;
            default: return 0;
        }
    }
    return real_fcntl(fd, linux_cmd, arg);
}

/* ── strerror_r ──────────────────────────────────────────────── */

extern char *__strerror_r(int errnum, char *buf, size_t buflen);
int macify_strerror_r(int errnum, char *buf, size_t buflen) __asm__("strerror_r");
int macify_strerror_r(int errnum, char *buf, size_t buflen) {
    char *str = __strerror_r(errnum, buf, buflen);
    if (str && str != buf) {
        size_t len = strlen(str);
        if (len >= buflen) len = buflen - 1;
        memcpy(buf, str, len);
        buf[len] = '\0';
    }
    return 0;
}

/* ── __xstat / __lxstat / __fxstat ─────────────────────────────
 * glibc's old-style stat wrappers. Rust's libc crate may use these
 * instead of stat/lstat/fstat on some platforms. Without shims,
 * these bypass our macOS struct stat translation. */

/* macos_stat and translate_stat are defined below in the stat section.
 * We forward-declare them here. */
struct macos_stat;
static void translate_stat(const struct stat *ls, struct macos_stat *ms);

int macify___xstat(int ver, const char *path, struct macos_stat *buf) __asm__("__xstat");
int macify___xstat(int ver, const char *path, struct macos_stat *buf) {
    static int (*real)(int, const char *, struct stat *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "__xstat");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos) return real(ver, path, (struct stat *)buf);
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    struct stat ls;
    int ret = real(ver, eff, &ls);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: __xstat(\"%s\") = %d errno=%d st_mode=0%o\n",
            path ? path : "(null)", ret, ret ? errno : 0,
            ret == 0 ? ls.st_mode : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    return ret;
}

int macify___lxstat(int ver, const char *path, struct macos_stat *buf) __asm__("__lxstat");
int macify___lxstat(int ver, const char *path, struct macos_stat *buf) {
    static int (*real)(int, const char *, struct stat *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "__lxstat");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos) return real(ver, path, (struct stat *)buf);
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    struct stat ls;
    int ret = real(ver, eff, &ls);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: __lxstat(\"%s\") = %d errno=%d\n",
            path ? path : "(null)", ret, ret ? errno : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    return ret;
}

int macify___fxstat(int ver, int fd, struct macos_stat *buf) __asm__("__fxstat");
int macify___fxstat(int ver, int fd, struct macos_stat *buf) {
    static int (*real)(int, int, struct stat *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "__fxstat");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos) return real(ver, fd, (struct stat *)buf);
    struct stat ls;
    int ret = real(ver, fd, &ls);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: __fxstat(%d) = %d errno=%d\n", fd, ret, ret ? errno : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    return ret;
}

/* __xstat64 / __lxstat64 / __fxstat64 — 64-bit variants */
int macify___xstat64(int ver, const char *path, struct macos_stat *buf) __asm__("__xstat64");
int macify___xstat64(int ver, const char *path, struct macos_stat *buf) {
    return macify___xstat(ver, path, buf);
}

int macify___lxstat64(int ver, const char *path, struct macos_stat *buf) __asm__("__lxstat64");
int macify___lxstat64(int ver, const char *path, struct macos_stat *buf) {
    return macify___lxstat(ver, path, buf);
}

int macify___fxstat64(int ver, int fd, struct macos_stat *buf) __asm__("__fxstat64");
int macify___fxstat64(int ver, int fd, struct macos_stat *buf) {
    return macify___fxstat(ver, fd, buf);
}

/* ── stat / lstat / fstat ────────────────────────────────────── */

/* macOS x86_64 struct stat (with _DARWIN_C_SOURCE / 64-bit ino_t).
 * Field order and padding MUST match the macOS ABI exactly.
 * Verified empirically by disassembling ls_macos: it reads st_mode at
 * offset 4, st_ino at offset 8 — so the layout is:
 *   st_dev(4) st_mode(2) st_nlink(2) st_ino(8) st_uid(4) st_gid(4)
 *   st_rdev(4) _pad(4) st_atim(16) st_mtim(16) st_ctim(16)
 *   st_birthtim(16) st_size(8) st_blocks(8) st_blksize(4)
 *   st_flags(4) st_gen(4) st_lspare(4) st_qspare[2](16)
 * Total: 144 bytes. */
struct macos_stat {
    int32_t       st_dev;        /* offset 0  */
    uint16_t      st_mode;       /* offset 4  */
    uint16_t      st_nlink;      /* offset 6  */
    uint64_t      st_ino;        /* offset 8  */
    uint32_t      st_uid;        /* offset 16 */
    uint32_t      st_gid;        /* offset 20 */
    int32_t       st_rdev;       /* offset 24 */
    int32_t       _pad0;         /* offset 28 (alignment padding) */
    struct timespec st_atim;     /* offset 32 */
    struct timespec st_mtim;     /* offset 48 */
    struct timespec st_ctim;     /* offset 64 */
    struct timespec st_birthtim; /* offset 80 */
    int64_t       st_size;       /* offset 96 */
    int64_t       st_blocks;     /* offset 104 */
    int32_t       st_blksize;    /* offset 112 */
    uint32_t      st_flags;      /* offset 116 */
    uint32_t      st_gen;        /* offset 120 */
    int32_t       st_lspare;     /* offset 124 */
    int64_t       st_qspare[2];  /* offset 128 */
};

static void translate_stat(const struct stat *ls, struct macos_stat *ms) {
    memset(ms, 0, sizeof(*ms));
    ms->st_dev = (int32_t)ls->st_dev;
    ms->st_mode = (uint16_t)ls->st_mode;
    ms->st_nlink = (uint16_t)ls->st_nlink;
    ms->st_ino = ls->st_ino;
    ms->st_uid = ls->st_uid;
    ms->st_gid = ls->st_gid;
    ms->st_rdev = (int32_t)ls->st_rdev;
    ms->st_atim = ls->st_atim;
    ms->st_mtim = ls->st_mtim;
    ms->st_ctim = ls->st_ctim;
    ms->st_birthtim = ls->st_ctim;
    ms->st_size = ls->st_size;
    ms->st_blocks = ls->st_blocks;
    ms->st_blksize = ls->st_blksize;
}

static int (*real_stat)(const char *, struct stat *);
static int (*real_lstat)(const char *, struct stat *);
static int (*real_fstat)(int, struct stat *);

int macify_stat(const char *path, struct macos_stat *buf) __asm__("stat");
int macify_stat(const char *path, struct macos_stat *buf) {
    if (!real_stat) real_stat = dlsym(RTLD_NEXT, "stat");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos)
        return real_stat(path, (struct stat *)buf);
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    struct stat ls;
    int ret = real_stat(eff, &ls);
    /* Don't clear errno — glibc doesn't, and Rust reads errno.
     * But also don't leave stale ENOENT from a prior failed call.
     * The correct behavior: errno is only valid when the call fails.
     * If ret==0, errno is undefined (glibc may or may not clear it).
     * Rust only reads errno when the call fails, so we don't need
     * to do anything. */
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: stat(\"%s\"%s) = %d errno=%d st_mode=0%o st_size=%ld\n",
            path ? path : "(null)",
            eff != path ? " [translated]" : "", ret, ret ? errno : 0,
            ret == 0 ? ls.st_mode : 0, ret == 0 ? (long)ls.st_size : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) {
        translate_stat(&ls, buf);
        /* Clear errno on success — glibc may leave stale errno from
         * a prior failed call (e.g. open of non-existent config file).
         * Rust binaries like bat read errno via __error() even after
         * successful calls in some code paths. */
        errno = 0;
    }
    return ret;
}

int macify_lstat(const char *path, struct macos_stat *buf) __asm__("lstat");
int macify_lstat(const char *path, struct macos_stat *buf) {
    if (!real_lstat) real_lstat = dlsym(RTLD_NEXT, "lstat");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos)
        return real_lstat(path, (struct stat *)buf);
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    struct stat ls;
    int ret = real_lstat(eff, &ls);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: lstat(\"%s\"%s) = %d errno=%d\n",
            path ? path : "(null)",
            eff != path ? " [translated]" : "", ret, ret ? errno : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    return ret;
}

int macify_fstat(int fd, struct macos_stat *buf) __asm__("fstat");
int macify_fstat(int fd, struct macos_stat *buf) {
    if (!real_fstat) real_fstat = dlsym(RTLD_NEXT, "fstat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_fstat(fd, (struct stat *)buf);
    struct stat ls;
    int ret = real_fstat(fd, &ls);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: fstat(%d) = %d errno=%d\n", fd, ret, ret ? errno : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    return ret;
}

/* ── fstatat ─────────────────────────────────────────────────── */

int macify_fstatat(int dirfd, const char *pathname, struct macos_stat *buf, int flags) __asm__("fstatat");
int macify_fstatat(int dirfd, const char *pathname, struct macos_stat *buf, int flags) {
    static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
    if (!real_fstatat) real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_fstatat(dirfd, pathname, (struct stat *)buf, flags);
    if (dirfd == -2) dirfd = -100;
    int linux_flags = 0;
    if (flags & 0x0200) linux_flags |= 0x0100;
    if (flags & 0x0400) linux_flags |= 0x0400;
    if (flags & 0x0800) linux_flags |= 0x0200;
    if (flags & 0x1000) linux_flags |= 0x0200;
    const char *eff = pathname;
    char tp[4096];
    if (pathname) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, tp, sizeof(tp)) == 0) eff = tp;
    }
    struct stat ls;
    int ret = real_fstatat(dirfd, eff, &ls, linux_flags);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: fstatat(%d, \"%s\", 0x%x->0x%x) = %d errno=%d\n",
            dirfd, pathname ? pathname : "(null)", flags, linux_flags, ret, ret ? errno : 0);
        (void)write(2, b, n);
    }
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    return ret;
}

/* stat64 / lstat64 / fstat64 / fstatat64 — glibc's 64-bit stat variants.
 * Rust's libc crate may call these instead of stat/lstat/fstat on
 * 64-bit Linux. Without shims, these bypass our macOS struct translation. */
int macify_stat64(const char *path, struct macos_stat *buf) __asm__("stat64");
int macify_stat64(const char *path, struct macos_stat *buf) {
    return macify_stat(path, buf);
}

int macify_lstat64(const char *path, struct macos_stat *buf) __asm__("lstat64");
int macify_lstat64(const char *path, struct macos_stat *buf) {
    return macify_lstat(path, buf);
}

int macify_fstat64(int fd, struct macos_stat *buf) __asm__("fstat64");
int macify_fstat64(int fd, struct macos_stat *buf) {
    return macify_fstat(fd, buf);
}

int macify_fstatat64(int dirfd, const char *pathname, struct macos_stat *buf, int flags) __asm__("fstatat64");
int macify_fstatat64(int dirfd, const char *pathname, struct macos_stat *buf, int flags) {
    return macify_fstatat(dirfd, pathname, buf, flags);
}

/* ── access ──────────────────────────────────────────────────── */
/* access — check file accessibility. Apply prefix path translation. */
int macify_access(const char *path, int mode) __asm__("access");
int macify_access(const char *path, int mode) {
    static int (*real_access)(const char *, int) = NULL;
    if (!real_access) real_access = dlsym(RTLD_NEXT, "access");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos)
        return real_access(path, mode);
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    int r = real_access(eff, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: access(\"%s\", %d) = %d errno=%d\n",
            path ? path : "(null)", mode, r, r ? errno : 0);
        (void)write(2, b, n);
    }
    if (r == 0) errno = 0;
    return r;
}

/* ── faccessat ───────────────────────────────────────────────── */
/* macOS AT_FDCWD = -2, Linux AT_FDCWD = -100.
 * macOS AT_EACCESS = 0x0010, Linux AT_EACCESS = 0x0200.
 * Without translation, glibc's faccessat returns EINVAL for AT_FDCWD=-2,
 * which breaks sort/coreutils' file readability check. */
int macify_faccessat(int dirfd, const char *pathname, int mode, int flags) __asm__("faccessat");
int macify_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    static int (*real_faccessat)(int, const char *, int, int) = NULL;
    if (!real_faccessat) real_faccessat = dlsym(RTLD_NEXT, "faccessat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_faccessat(dirfd, pathname, mode, flags);
    if (dirfd == -2) dirfd = -100;  /* AT_FDCWD */
    int linux_flags = 0;
    if (flags & 0x0010) linux_flags |= 0x0200;  /* AT_EACCESS */
    const char *eff = pathname;
    char tp[4096];
    if (pathname) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, tp, sizeof(tp)) == 0) eff = tp;
    }
    return real_faccessat(dirfd, eff, mode, linux_flags);
}

/* ── unlinkat / linkat / symlinkat / readlinkat ────────────────
 * macOS AT_FDCWD = -2, Linux AT_FDCWD = -100.
 * These *at functions need AT_FDCWD translation for macOS callers. */

int macify_unlinkat(int dirfd, const char *pathname, int flags) __asm__("unlinkat");
int macify_unlinkat(int dirfd, const char *pathname, int flags) {
    static int (*real_unlinkat)(int, const char *, int) = NULL;
    if (!real_unlinkat) real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_unlinkat(dirfd, pathname, flags);
    if (dirfd == -2) dirfd = -100;  /* AT_FDCWD */
    int linux_flags = 0;
    if (flags & 0x0200) linux_flags |= 0x0100;  /* AT_REMOVEDIR */
    const char *eff = pathname;
    char tp[4096];
    if (pathname) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, tp, sizeof(tp)) == 0) eff = tp;
    }
    return real_unlinkat(dirfd, eff, linux_flags);
}

int macify_linkat(int fromfd, const char *from, int tofd, const char *to, int flags) __asm__("linkat");
int macify_linkat(int fromfd, const char *from, int tofd, const char *to, int flags) {
    static int (*real_linkat)(int, const char *, int, const char *, int) = NULL;
    if (!real_linkat) real_linkat = dlsym(RTLD_NEXT, "linkat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_linkat(fromfd, from, tofd, to, flags);
    if (fromfd == -2) fromfd = -100;
    if (tofd == -2) tofd = -100;
    int linux_flags = 0;
    if (flags & 0x0400) linux_flags |= 0x0200;  /* AT_SYMLINK_FOLLOW */
    const char *eff_from = from, *eff_to = to;
    char tp_from[4096], tp_to[4096];
    extern int macify_translate_path(const char *, char *, size_t);
    if (from && macify_translate_path(from, tp_from, sizeof(tp_from)) == 0) eff_from = tp_from;
    if (to && macify_translate_path(to, tp_to, sizeof(tp_to)) == 0) eff_to = tp_to;
    return real_linkat(fromfd, eff_from, tofd, eff_to, linux_flags);
}

int macify_symlinkat(const char *target, int dirfd, const char *linkpath) __asm__("symlinkat");
int macify_symlinkat(const char *target, int dirfd, const char *linkpath) {
    static int (*real_symlinkat)(const char *, int, const char *) = NULL;
    if (!real_symlinkat) real_symlinkat = dlsym(RTLD_NEXT, "symlinkat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_symlinkat(target, dirfd, linkpath);
    if (dirfd == -2) dirfd = -100;
    const char *eff = linkpath;
    char tp[4096];
    if (linkpath) {
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(linkpath, tp, sizeof(tp)) == 0) eff = tp;
    }
    return real_symlinkat(target, dirfd, eff);
}

ssize_t macify_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) __asm__("readlinkat");
ssize_t macify_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
    if (!real_readlinkat) real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_readlinkat(dirfd, pathname, buf, bufsiz);
    if (dirfd == -2) dirfd = -100;
    const char *eff = pathname;
    char tp[4096];
    if (pathname) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, tp, sizeof(tp)) == 0) eff = tp;
    }
    return real_readlinkat(dirfd, eff, buf, bufsiz);
}

/* utimensat — set file timestamps with nanosecond precision.
 * macOS AT_FDCWD = -2, Linux AT_FDCWD = -100.
 * macOS AT_SYMLINK_NOFOLLOW = 0x0200, Linux = 0x0100.
 * Without AT_FDCWD translation, glibc returns EINVAL. */
int macify_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) __asm__("utimensat");
int macify_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
    static int (*real_utimensat)(int, const char *, const struct timespec[2], int) = NULL;
    if (!real_utimensat) real_utimensat = dlsym(RTLD_NEXT, "utimensat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_utimensat(dirfd, pathname, times, flags);
    if (dirfd == -2) dirfd = -100;
    /* macOS AT_SYMLINK_NOFOLLOW = 0x0200, Linux = 0x0100.
     * Only translate known flags; ignore unknown macOS-specific bits. */
    int linux_flags = 0;
    if (flags & 0x0200) linux_flags |= 0x0100;  /* AT_SYMLINK_NOFOLLOW */
    const char *eff = pathname;
    char tp[4096];
    if (pathname) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(pathname)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(pathname, tp, sizeof(tp)) == 0) eff = tp;
    }
    int r = real_utimensat(dirfd, eff, times, linux_flags);
    if (r < 0 && errno == EINVAL) {
        /* If utimensat fails with EINVAL, the times array may have
         * macOS-specific UTIME_NOW/UTIME_OMIT values. Try with NULL
         * times (sets both to current time). */
        r = real_utimensat(dirfd, eff, NULL, linux_flags);
    }
    return r;
}

/* futimens — set file timestamps by fd. */
int macify_futimens(int fd, const struct timespec times[2]) __asm__("futimens");
int macify_futimens(int fd, const struct timespec times[2]) {
    static int (*real_futimens)(int, const struct timespec[2]) = NULL;
    if (!real_futimens) real_futimens = dlsym(RTLD_NEXT, "futimens");
    return real_futimens(fd, times);
}

/* ── passwd ──────────────────────────────────────────────────── */

/* macOS struct passwd layout (x86_64):
 *   pw_name, pw_passwd, pw_uid, pw_gid, pw_change, pw_class,
 *   pw_gecos, pw_dir, pw_shell, pw_expire
 * (different field order from Linux's struct passwd!) */
struct macos_passwd {
    char    *pw_name;     /* offset 0  */
    char    *pw_passwd;   /* offset 8  */
    uid_t    pw_uid;      /* offset 16 */
    gid_t    pw_gid;      /* offset 20 */
    time_t   pw_change;   /* offset 24 */
    char    *pw_class;    /* offset 32 */
    char    *pw_gecos;    /* offset 40 */
    char    *pw_dir;      /* offset 48 */
    char    *pw_shell;    /* offset 56 */
    time_t   pw_expire;   /* offset 64 */
};

static __thread struct macos_passwd macos_pw;
static __thread char macos_pw_name[256], macos_pw_dir[256], macos_pw_shell[256];

struct passwd *macify_getpwuid(uid_t uid) __asm__("getpwuid");
struct passwd *macify_getpwuid(uid_t uid) {
    static struct passwd *(*real)(uid_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwuid");
    if (!real) return NULL;
    struct passwd *lp = real(uid);
    if (!lp) return NULL;
    strncpy(macos_pw_name, lp->pw_name, 255); macos_pw_name[255] = '\0';
    strncpy(macos_pw_dir, lp->pw_dir, 255); macos_pw_dir[255] = '\0';
    strncpy(macos_pw_shell, lp->pw_shell, 255); macos_pw_shell[255] = '\0';
    macos_pw.pw_name = macos_pw_name;
    macos_pw.pw_passwd = lp->pw_passwd;
    macos_pw.pw_uid = lp->pw_uid;
    macos_pw.pw_gid = lp->pw_gid;
    macos_pw.pw_change = 0;
    macos_pw.pw_class = "";
    macos_pw.pw_gecos = lp->pw_gecos;
    macos_pw.pw_dir = macos_pw_dir;
    macos_pw.pw_shell = macos_pw_shell;
    macos_pw.pw_expire = 0;
    return (struct passwd *)&macos_pw;
}

int macify_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) __asm__("getpwuid_r");
int macify_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    static int (*real)(uid_t, struct passwd *, char *, size_t, struct passwd **) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwuid_r");
    if (!real) { errno = ENOSYS; return -1; }
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: getpwuid_r(%u) [enter]\n", uid);
        (void)write(2, b, n);
    }
    /* Call real getpwuid_r with a Linux-format struct passwd.
     * Then translate to macOS format in the caller's buffer.
     * CRITICAL: The caller (bat/Rust) expects macOS passwd layout.
     * We must use a separate Linux struct for the real call, then
     * copy fields to the macOS-format struct. */
    struct passwd linux_pw;
    char linux_buf[4096];
    struct passwd *linux_result = NULL;
    int r = real(uid, &linux_pw, linux_buf, sizeof(linux_buf), &linux_result);
    if (r == 0 && linux_result) {
        /* Translate to macOS format in caller's buffer */
        struct macos_passwd *mp = (struct macos_passwd *)pwd;
        size_t need = 0;
        need += strlen(linux_pw.pw_name) + 1;
        if (linux_pw.pw_passwd) need += strlen(linux_pw.pw_passwd) + 1;
        if (linux_pw.pw_gecos) need += strlen(linux_pw.pw_gecos) + 1;
        need += strlen(linux_pw.pw_dir) + 1;
        need += strlen(linux_pw.pw_shell) + 1;
        if (need > buflen) { *result = NULL; return ERANGE; }
        char *p = buf;
        mp->pw_name = p; strcpy(p, linux_pw.pw_name); p += strlen(p) + 1;
        if (linux_pw.pw_passwd) { mp->pw_passwd = p; strcpy(p, linux_pw.pw_passwd); p += strlen(p) + 1; }
        else mp->pw_passwd = NULL;
        mp->pw_uid = linux_pw.pw_uid;
        mp->pw_gid = linux_pw.pw_gid;
        mp->pw_change = 0;
        mp->pw_class = NULL;
        if (linux_pw.pw_gecos) { mp->pw_gecos = p; strcpy(p, linux_pw.pw_gecos); p += strlen(p) + 1; }
        else mp->pw_gecos = NULL;
        mp->pw_dir = p; strcpy(p, linux_pw.pw_dir); p += strlen(p) + 1;
        mp->pw_shell = p; strcpy(p, linux_pw.pw_shell); p += strlen(p) + 1;
        mp->pw_expire = 0;
        *result = (struct passwd *)mp;
    } else {
        *result = NULL;
    }
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: getpwuid_r(%u) = %d result=%p dir=%s\n",
            uid, r, result ? (void *)*result : NULL,
            (r == 0 && result && *result) ? ((struct macos_passwd *)*result)->pw_dir : "(null)");
        (void)write(2, b, n);
    }
    return r;
}

struct passwd *macify_getpwnam(const char *name) __asm__("getpwnam");
struct passwd *macify_getpwnam(const char *name) {
    static struct passwd *(*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwnam");
    if (!real) return NULL;
    struct passwd *lp = real(name);
    if (!lp) return NULL;
    strncpy(macos_pw_name, lp->pw_name, 255); macos_pw_name[255] = '\0';
    strncpy(macos_pw_dir, lp->pw_dir, 255); macos_pw_dir[255] = '\0';
    strncpy(macos_pw_shell, lp->pw_shell, 255); macos_pw_shell[255] = '\0';
    macos_pw.pw_name = macos_pw_name;
    macos_pw.pw_passwd = lp->pw_passwd;
    macos_pw.pw_uid = lp->pw_uid;
    macos_pw.pw_gid = lp->pw_gid;
    macos_pw.pw_change = 0;
    macos_pw.pw_class = "";
    macos_pw.pw_gecos = lp->pw_gecos;
    macos_pw.pw_dir = macos_pw_dir;
    macos_pw.pw_shell = macos_pw_shell;
    macos_pw.pw_expire = 0;
    return (struct passwd *)&macos_pw;
}

/* ── unlink / rename / rmdir / chdir / close ─────────────────── */
/* Tracing shims for path-based functions that can return ENOENT,
 * to identify which call bat fails on. */

int macify_unlink(const char *path) __asm__("unlink");
int macify_unlink(const char *path) {
    static int (*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "unlink");
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_should_hide_path(const char *);
        if (macify_should_hide_path(path)) { errno = ENOENT; return -1; }
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    int r = real(eff);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: unlink(\"%s\") = %d errno=%d\n",
            path ? path : "(null)", r, r ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

int macify_rename(const char *old, const char *newp) __asm__("rename");
int macify_rename(const char *old, const char *newp) {
    static int (*real)(const char *, const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "rename");
    const char *eff_old = old, *eff_new = newp;
    char tp_old[4096], tp_new[4096];
    extern int macify_translate_path(const char *, char *, size_t);
    if (old && macify_translate_path(old, tp_old, sizeof(tp_old)) == 0) eff_old = tp_old;
    if (newp && macify_translate_path(newp, tp_new, sizeof(tp_new)) == 0) eff_new = tp_new;
    int r = real(eff_old, eff_new);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: rename(\"%s\", \"%s\") = %d errno=%d\n",
            old ? old : "(null)", newp ? newp : "(null)", r, r ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

int macify_rmdir(const char *path) __asm__("rmdir");
int macify_rmdir(const char *path) {
    static int (*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "rmdir");
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    int r = real(eff);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: rmdir(\"%s\") = %d errno=%d\n",
            path ? path : "(null)", r, r ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

int macify_chdir(const char *path) __asm__("chdir");
int macify_chdir(const char *path) {
    static int (*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "chdir");
    const char *eff = path;
    char tp[4096];
    if (path) {
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    }
    int r = real(eff);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: chdir(\"%s\") = %d errno=%d\n",
            path ? path : "(null)", r, r ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

int macify_close(int fd) __asm__("close");
int macify_close(int fd) {
    static int (*real)(int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "close");
    int r = real(fd);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: close(%d) = %d errno=%d\n", fd, r, r ? errno : 0);
        (void)write(2, b, n);
    }
    return r;
}

/* ── sysconf ─────────────────────────────────────────────────── */
/* macOS _SC_* constants differ from Linux _SC_* constants.
 * Without translation, macOS binaries call sysconf(macOS_value) which
 * glibc interprets as a DIFFERENT parameter, returning -1 or wrong data.
 *
 * Key mappings:
 *   macOS _SC_NPROCESSORS_ONLN (58) → Linux _SC_NPROCESSORS_ONLN (84)
 *   macOS _SC_NPROCESSORS_CONF (57) → Linux _SC_NPROCESSORS_CONF (83)
 *   macOS _SC_PAGESIZE (29)         → Linux _SC_PAGESIZE (30)
 *   macOS _SC_CLK_TCK (3)           → Linux _SC_CLK_TCK (2)
 *   macOS _SC_ARG_MAX (1)           → Linux _SC_ARG_MAX (0)
 *   macOS _SC_OPEN_MAX (5)          → Linux _SC_OPEN_MAX (4)
 *   macOS _SC_PHYS_PAGES (200)      → Linux _SC_PHYS_PAGES (85)
 *
 * IMPORTANT: Only translate for macOS callers. glibc internally calls
 * sysconf (e.g. during dlsym, getpwuid_r), and those must use Linux
 * parameter numbers directly. */
long macify_sysconf(int name) __asm__("sysconf");
long macify_sysconf(int name) {
    LAZY_INIT_IO();

    /* Only translate for macOS callers — glibc's internal sysconf calls
     * use Linux parameter numbers and must not be translated. */
    if (!macify_caller_is_macos_text(__builtin_return_address(0))) {
        return real_sysconf(name);
    }

    /* Translate macOS _SC_* to Linux _SC_* */
    int linux_name = name;
    switch (name) {
        case 1:  linux_name = _SC_ARG_MAX; break;             /* macOS _SC_ARG_MAX */
        case 2:  linux_name = _SC_CHILD_MAX; break;           /* macOS _SC_CHILD_MAX */
        case 3:  linux_name = _SC_CLK_TCK; break;             /* macOS _SC_CLK_TCK */
        case 4:  linux_name = _SC_NGROUPS_MAX; break;         /* macOS _SC_NGROUPS_MAX */
        case 5:  linux_name = _SC_OPEN_MAX; break;            /* macOS _SC_OPEN_MAX */
        case 6:  linux_name = _SC_JOB_CONTROL; break;         /* macOS _SC_JOB_CONTROL */
        case 7:  linux_name = _SC_SAVED_IDS; break;           /* macOS _SC_SAVED_IDS */
        case 8:  linux_name = _SC_VERSION; break;             /* macOS _SC_VERSION */
        case 26: linux_name = _SC_STREAM_MAX; break;          /* macOS _SC_STREAM_MAX */
        case 27: linux_name = _SC_TZNAME_MAX; break;          /* macOS _SC_TZNAME_MAX */
        case 29: linux_name = _SC_PAGESIZE; break;            /* macOS _SC_PAGESIZE */
        case 57: linux_name = _SC_NPROCESSORS_CONF; break;    /* macOS _SC_NPROCESSORS_CONF */
        case 58: linux_name = _SC_NPROCESSORS_ONLN; break;    /* macOS _SC_NPROCESSORS_ONLN */
        case 200: linux_name = _SC_PHYS_PAGES; break;         /* macOS _SC_PHYS_PAGES */
        default: linux_name = name; break;  /* pass through for unknown */
    }

    long r = real_sysconf(linux_name);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: sysconf(%d->%d) = %ld errno=%d\n",
            name, linux_name, r, r == -1 ? errno : 0);
        (void)write(2, b, n);
    }
    if (r != -1) errno = 0;
    return r;
}
