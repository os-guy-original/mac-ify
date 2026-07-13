/* dirent.c — directory operations: opendir, fdopendir, readdir, readdir_r */
#include "io_internal.h"
#include <dirent.h>

struct macos_dirent {
    uint64_t d_ino;
    uint64_t d_seekoff;
    uint16_t d_reclen;
    uint16_t d_namlen;
    uint8_t  d_type;
    char     d_name[1024];
};

DIR *macify_fdopendir(int fd) __asm__("fdopendir");
DIR *macify_fdopendir(int fd) {
    static DIR *(*real)(int) = NULL;
    if (!real) real = real_dlsym(RTLD_NEXT, "fdopendir");
    return real(fd);
}

/* opendir — translate macOS paths to prefix paths.
 * macOS binaries call opendir("/System/Library/...") which should
 * be translated to ~/.macify/System/Library/... */
DIR *macify_opendir(const char *name) __asm__("opendir");
DIR *macify_opendir(const char *name) {
    static DIR *(*real_opendir)(const char *) = NULL;
    if (!real_opendir) real_opendir = real_dlsym(RTLD_NEXT, "opendir");
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return real_opendir(name);
    extern int macify_should_hide_path(const char *);
    extern int macify_translate_path(const char *, char *, size_t);
    if (macify_should_hide_path(name)) { errno = ENOENT; return NULL; }
    char translated[PATH_MAX];
    DIR *r;
    if (macify_translate_path(name, translated, sizeof(translated)) == 0) {
        r = real_opendir(translated);
    } else {
        r = real_opendir(name);
    }
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: opendir(\"%s\") = %p errno=%d\n",
            name ? name : "(null)", (void*)r, r ? 0 : errno);
        (void)write(2, b, n);
    }
    return r;
}

DIR *opendirat(int dirfd, const char *name, int flags) {
    (void)flags;
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) real_openat = real_dlsym(RTLD_NEXT, "openat");
    int fd = real_openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return NULL;
    DIR *dir = fdopendir(fd);
    if (!dir) close(fd);
    return dir;
}

static int (*real_readdir_r)(DIR *, struct dirent *, struct dirent **);

int macify_readdir_r(DIR *dirp, struct macos_dirent *entry, struct macos_dirent **result) __asm__("readdir_r");
int macify_readdir_r(DIR *dirp, struct macos_dirent *entry, struct macos_dirent **result) {
    if (!real_readdir_r) real_readdir_r = real_dlsym(RTLD_NEXT, "readdir_r");
    struct dirent le;
    struct dirent *lr = NULL;
    int ret = real_readdir_r(dirp, &le, &lr);
    if (ret == 0 && lr && entry) {
        memset(entry, 0, sizeof(*entry));
        entry->d_ino = le.d_ino;
        entry->d_reclen = le.d_reclen;
        entry->d_type = le.d_type;
        size_t namlen = strlen(le.d_name);
        if (namlen > 1023) namlen = 1023;
        memcpy(entry->d_name, le.d_name, namlen);
        entry->d_name[namlen] = '\0';
        entry->d_namlen = namlen;
        *result = entry;
    } else if (ret == 0) {
        *result = NULL;
    }
    return ret;
}

static __thread struct macos_dirent macos_readdir_buf;

/* Static helper — does NOT go through PLT. Avoids glibc's readdir
 * being called instead of ours when called from readdir$INODE64.
 * If macify_readdir (exported as "readdir") is called from
 * readdir$INODE64, the call may go through the PLT and resolve to
 * glibc's readdir, returning Linux-format dirent instead of macOS. */
static struct macos_dirent *do_readdir_impl(DIR *dirp) {
    static struct dirent *(*real_readdir)(DIR *) = NULL;
    if (!real_readdir) real_readdir = real_dlsym(RTLD_NEXT, "readdir");
    struct dirent *le = real_readdir(dirp);
    if (!le) return NULL;
    memset(&macos_readdir_buf, 0, sizeof(macos_readdir_buf));
    macos_readdir_buf.d_ino = le->d_ino;
    macos_readdir_buf.d_seekoff = 0;
    macos_readdir_buf.d_reclen = le->d_reclen;
    macos_readdir_buf.d_namlen = (uint16_t)strlen(le->d_name);
    macos_readdir_buf.d_type = le->d_type;
    strncpy(macos_readdir_buf.d_name, le->d_name, sizeof(macos_readdir_buf.d_name) - 1);
    macos_readdir_buf.d_name[sizeof(macos_readdir_buf.d_name) - 1] = '\0';
    return &macos_readdir_buf;
}

struct macos_dirent *macify_readdir(DIR *dirp) __asm__("readdir");
struct macos_dirent *macify_readdir(DIR *dirp) {
    return do_readdir_impl(dirp);
}

/* readdir$INODE64 — uses static helper to avoid PLT resolution issues. */
struct macos_dirent *macify_readdir_inode64(DIR *dirp) __asm__("readdir$INODE64");
struct macos_dirent *macify_readdir_inode64(DIR *dirp) {
    return do_readdir_impl(dirp);
}

/* opendir$INODE64 — macOS alias for opendir (64-bit inode variant).
 * CRITICAL: Do NOT delegate to macify_opendir — it checks
 * macify_caller_is_macos_text, which would return FALSE because the
 * return address is in this shim. Do the translation directly. */
DIR *macify_opendir_inode64(const char *name) __asm__("opendir$INODE64");
DIR *macify_opendir_inode64(const char *name) {
    static DIR *(*real_opendir)(const char *) = NULL;
    if (!real_opendir) real_opendir = real_dlsym(RTLD_NEXT, "opendir");
    if (!name) { errno = EFAULT; return NULL; }
    extern int macify_should_hide_path(const char *);
    extern int macify_translate_path(const char *, char *, size_t);
    if (macify_should_hide_path(name)) { errno = ENOENT; return NULL; }
    char translated[PATH_MAX];
    DIR *r;
    if (macify_translate_path(name, translated, sizeof(translated)) == 0) {
        r = real_opendir(translated);
    } else {
        r = real_opendir(name);
    }
    return r;
}
