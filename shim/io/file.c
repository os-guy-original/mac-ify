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
    int32_t       st_dev;
    uint16_t      st_mode;
    uint16_t      st_nlink;
    uint64_t      st_ino;
    uint32_t      st_uid;
    uint32_t      st_gid;
    int32_t       st_rdev;
    int32_t       _pad1;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    struct timespec st_birthtim;
    int64_t       st_size;
    int64_t       st_blocks;
    int32_t       st_blksize;
    uint32_t      st_flags;
    uint32_t      st_gen;
    int32_t       st_lspare;
    int64_t       st_qspare[2];
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
    if (ret == 0) { translate_stat(&ls, buf); errno = 0; }
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

struct passwd *macify_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) __asm__("getpwuid_r");
struct passwd *macify_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    static int (*real)(uid_t, struct passwd *, char *, size_t, struct passwd **) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpwuid_r");
    int r = real(uid, pwd, buf, buflen, result);
    if (r == 0 && *result) {
        (*result)->pw_name = pwd->pw_name;
    }
    return (struct passwd *)(long)r;
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
