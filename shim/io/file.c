/* file.c — file I/O: fcntl, strerror_r, stat/lstat/fstat, passwd */
#include "io_internal.h"
#include <sys/stat.h>
#include <pwd.h>

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

/* ── stat / lstat / fstat ────────────────────────────────────── */

struct macos_stat {
    int64_t       st_dev;          /* dev_t = 8 bytes on macOS x86_64 */
    uint16_t      st_mode;         /* mode_t = 2 bytes, offset 8 */
    uint16_t      st_nlink;        /* nlink_t = 2 bytes, offset 10 */
    uint32_t      _pad1;           /* padding, offset 12 (align ino to 16) */
    uint64_t      st_ino;          /* ino_t = 8 bytes, offset 16 */
    uint32_t      st_uid;          /* uid_t = 4 bytes, offset 24 */
    uint32_t      st_gid;          /* gid_t = 4 bytes, offset 28 */
    int64_t       st_rdev;         /* dev_t = 8 bytes, offset 32 */
    struct timespec st_atim;       /* 16 bytes, offset 40 */
    struct timespec st_mtim;       /* 16 bytes, offset 56 */
    struct timespec st_ctim;       /* 16 bytes, offset 72 */
    struct timespec st_birthtim;   /* 16 bytes, offset 88 */
    int64_t       st_size;         /* off_t = 8 bytes, offset 104 */
    int64_t       st_blocks;       /* blkcnt_t = 8 bytes, offset 112 */
    int32_t       st_blksize;      /* blksize_t = 4 bytes, offset 120 */
    uint32_t      st_flags;        /* offset 124 */
    uint32_t      st_gen;          /* offset 128 */
    int32_t       st_lspare;       /* offset 132 */
    int64_t       st_qspare[2];    /* offset 136, 16 bytes */
};

static void translate_stat(const struct stat *ls, struct macos_stat *ms) {
    memset(ms, 0, sizeof(*ms));
    ms->st_dev = (int64_t)ls->st_dev;
    ms->st_mode = (uint16_t)ls->st_mode;
    ms->st_nlink = (uint16_t)ls->st_nlink;
    ms->st_ino = ls->st_ino;
    ms->st_uid = ls->st_uid;
    ms->st_gid = ls->st_gid;
    ms->st_rdev = (int64_t)ls->st_rdev;
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
    if (!real_stat) { errno = ENOSYS; return -1; }
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_stat(path, (struct stat *)buf);
    struct stat ls;
    int ret = real_stat(path, &ls);
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: stat(\"%s\") = %d mode=0x%x size=%lld\n",
            path, ret, ret == 0 ? buf->st_mode : 0,
            ret == 0 ? (long long)buf->st_size : 0LL);
        (void)write(2, b, n);
    }
    return ret;
}

int macify_lstat(const char *path, struct macos_stat *buf) __asm__("lstat");
int macify_lstat(const char *path, struct macos_stat *buf) {
    if (!real_lstat) real_lstat = dlsym(RTLD_NEXT, "lstat");
    if (!real_lstat) { errno = ENOSYS; return -1; }
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_lstat(path, (struct stat *)buf);
    struct stat ls;
    int ret = real_lstat(path, &ls);
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: lstat(\"%s\") = %d mode=0x%x size=%lld\n",
            path, ret, ret == 0 ? buf->st_mode : 0,
            ret == 0 ? (long long)buf->st_size : 0LL);
        (void)write(2, b, n);
    }
    return ret;
}

int macify_fstat(int fd, struct macos_stat *buf) __asm__("fstat");
int macify_fstat(int fd, struct macos_stat *buf) {
    if (!real_fstat) real_fstat = dlsym(RTLD_NEXT, "fstat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_fstat(fd, (struct stat *)buf);
    struct stat ls;
    int ret = real_fstat(fd, &ls);
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: fstat(%d) = %d mode=0x%x size=%lld\n",
            fd, ret, ret == 0 ? buf->st_mode : 0,
            ret == 0 ? (long long)buf->st_size : 0LL);
        (void)write(2, b, n);
    }
    return ret;
}

/* ── fstatat ─────────────────────────────────────────────────── */

int macify_fstatat(int dirfd, const char *pathname, struct macos_stat *buf, int flags) __asm__("fstatat");
int macify_fstatat(int dirfd, const char *pathname, struct macos_stat *buf, int flags) {
    static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
    if (!real_fstatat) real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_fstatat(dirfd, pathname, (struct stat *)buf, flags);
    /* Translate macOS AT_FDCWD (-2) to Linux AT_FDCWD (-100) */
    int linux_dirfd = (dirfd == -2) ? -100 : dirfd;
    int linux_flags = 0;
    if (flags & 0x0200) linux_flags |= 0x0100;  /* AT_SYMLINK_NOFOLLOW */
    if (flags & 0x0400) linux_flags |= 0x0400;  /* AT_SYMLINK_FOLLOW */
    if (flags & 0x0800) linux_flags |= 0x0200;  /* AT_REMOVEDIR */
    if (flags & 0x1000) linux_flags |= 0x0200;
    struct stat ls;
    int ret = real_fstatat(linux_dirfd, pathname, &ls, linux_flags);
    if (ret == 0) translate_stat(&ls, buf);
    return ret;
}

/* ── passwd ──────────────────────────────────────────────────── */

static __thread struct { char *pw_name, *pw_passwd, *pw_gecos, *pw_dir, *pw_shell; uid_t pw_uid; gid_t pw_gid; long pw_change, pw_expire; char *pw_class; } macos_pw;
static __thread char macos_pw_name[256], macos_pw_dir[256], macos_pw_shell[256];

struct passwd *macify_getpwuid(uid_t uid) __asm__("getpwuid");
struct passwd *macify_getpwuid(uid_t uid) {
    static struct passwd *(*real)(uid_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwuid");
    struct passwd *lp = real(uid);
    if (!lp) return NULL;
    strncpy(macos_pw_name, lp->pw_name, 255);
    strncpy(macos_pw_dir, lp->pw_dir, 255);
    strncpy(macos_pw_shell, lp->pw_shell, 255);
    macos_pw.pw_name = macos_pw_name;
    macos_pw.pw_passwd = lp->pw_passwd;
    macos_pw.pw_uid = lp->pw_uid;
    macos_pw.pw_gid = lp->pw_gid;
    macos_pw.pw_gecos = lp->pw_gecos;
    macos_pw.pw_dir = macos_pw_dir;
    macos_pw.pw_shell = macos_pw_shell;
    macos_pw.pw_change = 0;
    macos_pw.pw_expire = 0;
    macos_pw.pw_class = "";
    return (struct passwd *)&macos_pw;
}

int macify_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) __asm__("getpwuid_r");
int macify_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    static int (*real)(uid_t, struct passwd *, char *, size_t, struct passwd **) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwuid_r");
    int r = real(uid, pwd, buf, buflen, result);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: getpwuid_r(%u) = %d result=%p dir=%s\n",
            uid, r, (void*)(result ? *result : NULL),
            (r == 0 && result && *result) ? (*result)->pw_dir : "(null)");
        (void)write(2, b, n);
    }
    return r;
}

struct passwd *macify_getpwnam(const char *name) __asm__("getpwnam");
struct passwd *macify_getpwnam(const char *name) {
    static struct passwd *(*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwnam");
    struct passwd *lp = real(name);
    if (!lp) return NULL;
    strncpy(macos_pw_name, lp->pw_name, 255);
    strncpy(macos_pw_dir, lp->pw_dir, 255);
    strncpy(macos_pw_shell, lp->pw_shell, 255);
    macos_pw.pw_name = macos_pw_name;
    macos_pw.pw_passwd = lp->pw_passwd;
    macos_pw.pw_uid = lp->pw_uid;
    macos_pw.pw_gid = lp->pw_gid;
    macos_pw.pw_gecos = lp->pw_gecos;
    macos_pw.pw_dir = macos_pw_dir;
    macos_pw.pw_shell = macos_pw_shell;
    macos_pw.pw_change = 0;
    macos_pw.pw_expire = 0;
    macos_pw.pw_class = "";
    return (struct passwd *)&macos_pw;
}

/* access — check file accessibility. macOS and Linux have the same
 * flag values (F_OK=0, R_OK=4, W_OK=2, X_OK=1), so we can pass through
 * directly to glibc. We override to add tracing and ensure it works. */
int macify_access(const char *path, int mode) __asm__("access");
int macify_access(const char *path, int mode) {
    static int (*real_access)(const char *, int) = NULL;
    if (!real_access) real_access = dlsym(RTLD_NEXT, "access");
    if (!real_access) { errno = ENOSYS; return -1; }
    int ret = real_access(path, mode);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: access(\"%s\", %d) = %d\n", path, mode, ret);
        (void)write(2, b, n);
    }
    return ret;
}

/* realpath — resolve absolute pathname. macOS and Linux have the same
 * behavior, so we pass through. We override to add tracing. */
char *macify_realpath(const char *path, char *resolved) __asm__("realpath");
char *macify_realpath(const char *path, char *resolved) {
    static char *(*real_realpath)(const char *, char *) = NULL;
    if (!real_realpath) real_realpath = dlsym(RTLD_NEXT, "realpath");
    char *ret = real_realpath(path, resolved);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: realpath(\"%s\") = %s\n",
            path ? path : "(null)", ret ? ret : "(null)");
        (void)write(2, b, n);
    }
    return ret;
}

/* getcwd — get current working directory. Pass through with tracing. */
char *macify_getcwd(char *buf, size_t size) __asm__("getcwd");
char *macify_getcwd(char *buf, size_t size) {
    static char *(*real_getcwd)(char *, size_t) = NULL;
    if (!real_getcwd) real_getcwd = dlsym(RTLD_NEXT, "getcwd");
    char *ret = real_getcwd(buf, size);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: getcwd() = %s\n", ret ? ret : "(null)");
        (void)write(2, b, n);
    }
    return ret;
}

/* isatty — check if fd is a terminal. bat calls isatty(1) to decide
 * whether to use color/paging. On Linux, isatty uses TCGETS ioctl.
 * On macOS, isatty uses TIOCGETA ioctl. We override to use Linux's
 * TCGETS so it works correctly. */
int macify_isatty(int fd) __asm__("isatty");
int macify_isatty(int fd) {
    static int (*real_isatty)(int) = NULL;
    if (!real_isatty) real_isatty = dlsym(RTLD_NEXT, "isatty");
    int ret = real_isatty(fd);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[128]; int n = snprintf(b, sizeof(b),
            "macify: isatty(%d) = %d\n", fd, ret);
        (void)write(2, b, n);
    }
    return ret;
}

/* ioctl — translate macOS terminal ioctls to Linux.
 * macOS uses different ioctl request codes for terminal operations.
 * Without translation, isatty() and TIOCGWINSZ fail with ENOTTY. */
int macify_ioctl(int fd, unsigned long request, ...) __asm__("ioctl");
int macify_ioctl(int fd, unsigned long request, ...) {
    static int (*real_ioctl)(int, unsigned long, ...) = NULL;
    if (!real_ioctl) real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    /* Translate macOS terminal ioctls to Linux */
    unsigned long linux_request = request;
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* macOS TIOCGETA (0x402c7413) → Linux TCGETS (0x5401) */
        if (request == 0x402c7413) linux_request = 0x5401;
        /* macOS TIOCGWINSZ (0x40087468) → Linux TIOCGWINSZ (0x5413) */
        else if (request == 0x40087468) linux_request = 0x5413;
        /* macOS TIOCGPGRP (0x40047477) → Linux TIOCGPGRP (0x540F) */
        else if (request == 0x40047477) linux_request = 0x540F;
        /* macOS FIONREAD (0x4004667F) → Linux FIONREAD (0x541B) */
        else if (request == 0x4004667F) linux_request = 0x541B;
        /* macOS FIONBIO (0x8004667E) → Linux FIONBIO (0x5421) */
        else if (request == 0x8004667E) linux_request = 0x5421;
        /* macOS TIOCMGET (0x4004746A) → Linux TIOCMGET (0x5415) */
        else if (request == 0x4004746A) linux_request = 0x5415;
    }

    int ret = real_ioctl(fd, linux_request, arg);
    if (getenv("MACIFY_TRACE_IOCTL")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: ioctl(%d, 0x%lx->0x%lx) = %d\n",
            fd, request, linux_request, ret);
        (void)write(2, b, n);
    }
    return ret;
}
