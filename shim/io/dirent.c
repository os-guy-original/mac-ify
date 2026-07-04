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
    if (!real) real = dlsym(RTLD_NEXT, "fdopendir");
    return real(fd);
}

DIR *opendirat(int dirfd, const char *name, int flags) {
    (void)flags;
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    int fd = real_openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return NULL;
    DIR *dir = fdopendir(fd);
    if (!dir) close(fd);
    return dir;
}

static int (*real_readdir_r)(DIR *, struct dirent *, struct dirent **);

int macify_readdir_r(DIR *dirp, struct macos_dirent *entry, struct macos_dirent **result) __asm__("readdir_r");
int macify_readdir_r(DIR *dirp, struct macos_dirent *entry, struct macos_dirent **result) {
    if (!real_readdir_r) real_readdir_r = dlsym(RTLD_NEXT, "readdir_r");
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

struct macos_dirent *macify_readdir(DIR *dirp) __asm__("readdir");
struct macos_dirent *macify_readdir(DIR *dirp) {
    static struct dirent *(*real_readdir)(DIR *) = NULL;
    if (!real_readdir) real_readdir = dlsym(RTLD_NEXT, "readdir");
    struct dirent *le = real_readdir(dirp);
    if (!le) return NULL;
    memset(&macos_readdir_buf, 0, sizeof(macos_readdir_buf));
    macos_readdir_buf.d_ino = le->d_ino;
    macos_readdir_buf.d_reclen = le->d_reclen;
    macos_readdir_buf.d_type = le->d_type;
    size_t namlen = strlen(le->d_name);
    if (namlen > 1023) namlen = 1023;
    memcpy(macos_readdir_buf.d_name, le->d_name, namlen);
    macos_readdir_buf.d_name[namlen] = '\0';
    macos_readdir_buf.d_namlen = namlen;
    return &macos_readdir_buf;
}
