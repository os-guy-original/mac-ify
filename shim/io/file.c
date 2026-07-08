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
    /* Prefix path translation */
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
    if (ret == 0) { translate_stat(&ls, buf);  }
    return ret;
}

int macify_lstat(const char *path, struct macos_stat *buf) __asm__("lstat");
int macify_lstat(const char *path, struct macos_stat *buf) {
    if (!real_lstat) real_lstat = dlsym(RTLD_NEXT, "lstat");
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (!is_macos)
        return real_lstat(path, (struct stat *)buf);
    /* Prefix path translation */
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
    if (ret == 0) { translate_stat(&ls, buf);  }
    return ret;
}

int macify_fstat(int fd, struct macos_stat *buf) __asm__("fstat");
int macify_fstat(int fd, struct macos_stat *buf) {
    if (!real_fstat) real_fstat = dlsym(RTLD_NEXT, "fstat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_fstat(fd, (struct stat *)buf);
    struct stat ls;
    int ret = real_fstat(fd, &ls);
    if (ret == 0) translate_stat(&ls, buf);
    return ret;
}

/* ── fstatat ─────────────────────────────────────────────────── */

int macify_fstatat(int dirfd, const char *pathname, struct macos_stat *buf, int flags) __asm__("fstatat");
int macify_fstatat(int dirfd, const char *pathname, struct macos_stat *buf, int flags) {
    static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
    if (!real_fstatat) real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_fstatat(dirfd, pathname, (struct stat *)buf, flags);
    /* macOS AT_FDCWD = -2, Linux AT_FDCWD = -100 */
    if (dirfd == -2) dirfd = -100;
    int linux_flags = 0;
    if (flags & 0x0200) linux_flags |= 0x0100;
    if (flags & 0x0400) linux_flags |= 0x0400;
    if (flags & 0x0800) linux_flags |= 0x0200;
    if (flags & 0x1000) linux_flags |= 0x0200;
    struct stat ls;
    int ret = real_fstatat(dirfd, pathname, &ls, linux_flags);
    if (ret == 0) translate_stat(&ls, buf);
    return ret;
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
    return real_faccessat(dirfd, pathname, mode, linux_flags);
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
    return real_unlinkat(dirfd, pathname, linux_flags);
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
    return real_linkat(fromfd, from, tofd, to, linux_flags);
}

int macify_symlinkat(const char *target, int dirfd, const char *linkpath) __asm__("symlinkat");
int macify_symlinkat(const char *target, int dirfd, const char *linkpath) {
    static int (*real_symlinkat)(const char *, int, const char *) = NULL;
    if (!real_symlinkat) real_symlinkat = dlsym(RTLD_NEXT, "symlinkat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_symlinkat(target, dirfd, linkpath);
    if (dirfd == -2) dirfd = -100;
    return real_symlinkat(target, dirfd, linkpath);
}

ssize_t macify_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) __asm__("readlinkat");
ssize_t macify_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
    if (!real_readlinkat) real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_readlinkat(dirfd, pathname, buf, bufsiz);
    if (dirfd == -2) dirfd = -100;
    return real_readlinkat(dirfd, pathname, buf, bufsiz);
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
    int r = real_utimensat(dirfd, pathname, times, linux_flags);
    if (r < 0 && errno == EINVAL) {
        /* If utimensat fails with EINVAL, the times array may have
         * macOS-specific UTIME_NOW/UTIME_OMIT values. Try with NULL
         * times (sets both to current time). */
        r = real_utimensat(dirfd, pathname, NULL, linux_flags);
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
    return real(uid, pwd, buf, buflen, result);
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
