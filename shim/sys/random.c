/* Split from misc.c */
#include "../shim.h"

void srandomdev(void) {
    unsigned int seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &seed, sizeof(seed));
        close(fd);
        srandom(seed);
    }
}

/* issetugid — macOS security check. Returns 1 if the process is running
 * setuid or setgid. On Linux, we check the real vs effective uid/gid. */
int issetugid(void) {
    return geteuid() != getuid() || getegid() != getgid();
}

/* gethostuuid — macOS-specific. Return a fake UUID. */
int gethostuuid(unsigned char *uuid_buf, const void *timeout) {
    (void)timeout;
    if (uuid_buf) {
        /* Fill with a deterministic fake UUID */
        memset(uuid_buf, 0, 16);
        uuid_buf[0] = 0x01;  /* fake */
    }
    return 0;
}

/* fsctl — macOS filesystem control. No Linux equivalent; return -1. */
int fsctl(const char *path, unsigned long request, void *data, unsigned options) {
    (void)path; (void)request; (void)data; (void)options;
    errno = ENOSYS;
    return -1;
}

/* statfs / fstatfs — macOS struct statfs differs from Linux's.
 * We override to translate the struct layout. */

struct macos_statfs {
    uint32_t f_bsize;        /* offset 0 */
    int32_t  f_iosize;       /* offset 4 */
    uint64_t f_blocks;       /* offset 8 */
    uint64_t f_bfree;        /* offset 16 */
    uint64_t f_bavail;       /* offset 24 */
    uint64_t f_files;        /* offset 32 */
    uint64_t f_ffree;        /* offset 40 */
    uint64_t f_fsid;         /* offset 48 (8 bytes) */
    uid_t    f_owner;        /* offset 56 */
    uint32_t f_type;         /* offset 60 */
    uint32_t f_flags;        /* offset 64 */
    uint32_t f_fssubtype;    /* offset 68 */
    char     f_fstypename[16]; /* offset 72 */
    char     f_mntonname[1024]; /* offset 88 */
    char     f_mntfromname[1024]; /* offset 1112 */
    uint32_t f_reserved[8];  /* offset 2136 */
};

int macify_statfs(const char *path, struct macos_statfs *buf) __asm__("statfs");
int macify_statfs(const char *path, struct macos_statfs *buf) {
    static int (*real_statfs)(const char *, struct statfs *) = NULL;
    if (!real_statfs) real_statfs = dlsym(RTLD_NEXT, "statfs");
    struct statfs linux_st;
    int ret = real_statfs(path, &linux_st);
    if (ret == 0 && buf) {
        memset(buf, 0, sizeof(*buf));
        buf->f_bsize = linux_st.f_bsize;
        buf->f_iosize = linux_st.f_bsize;
        buf->f_blocks = linux_st.f_blocks;
        buf->f_bfree = linux_st.f_bfree;
        buf->f_bavail = linux_st.f_bavail;
        buf->f_files = linux_st.f_files;
        buf->f_ffree = linux_st.f_ffree;
        memcpy(&buf->f_fsid, &linux_st.f_fsid, sizeof(buf->f_fsid));
        buf->f_owner = 0;
        buf->f_type = linux_st.f_type;
        strncpy(buf->f_fstypename, "ext4", sizeof(buf->f_fstypename) - 1);
    }
    return ret;
}

int macify_fstatfs(int fd, struct macos_statfs *buf) __asm__("fstatfs");
int macify_fstatfs(int fd, struct macos_statfs *buf) {
    static int (*real_fstatfs)(int, struct statfs *) = NULL;
    if (!real_fstatfs) real_fstatfs = dlsym(RTLD_NEXT, "fstatfs");
    struct statfs linux_st;
    int ret = real_fstatfs(fd, &linux_st);
    if (ret == 0 && buf) {
        memset(buf, 0, sizeof(*buf));
        buf->f_bsize = linux_st.f_bsize;
        buf->f_iosize = linux_st.f_bsize;
        buf->f_blocks = linux_st.f_blocks;
        buf->f_bfree = linux_st.f_bfree;
        buf->f_bavail = linux_st.f_bavail;
        buf->f_files = linux_st.f_files;
        buf->f_ffree = linux_st.f_ffree;
        memcpy(&buf->f_fsid, &linux_st.f_fsid, sizeof(buf->f_fsid));
        buf->f_type = linux_st.f_type;
        strncpy(buf->f_fstypename, "ext4", sizeof(buf->f_fstypename) - 1);
    }
    return ret;
}

/* getmntinfo — macOS function to get list of mounted filesystems.
 *   int getmntinfo(struct statfs **mntbufp, int flags);
 * Returns count of mounted filesystems; sets *mntbufp to an array of
 * struct statfs. The caller does NOT free the buffer (it's static).
 *
 * Linux equivalent: read /proc/mounts, call statfs on each mount point. */

/* $INODE64 variant — same function, different symbol name */
int macify_getmntinfo(struct macos_statfs **mntbufp, int flags) __asm__("getmntinfo");
int macify_getmntinfo(struct macos_statfs **mntbufp, int flags) {
    static struct macos_statfs mntbuf[64];
    static int mntcount = -1;

    if (mntcount < 0) {
        mntcount = 0;
        FILE *f = fopen("/proc/mounts", "r");
        if (!f) return 0;
        char line[4096];
        while (mntcount < 64 && fgets(line, sizeof(line), f)) {
            /* /proc/mounts format: device mountpoint fstype opts dump pass */
            char dev[256], mp[1024], fstype[64];
            if (sscanf(line, "%255s %1023s %63s", dev, mp, fstype) >= 3) {
                struct macos_statfs *m = &mntbuf[mntcount];
                memset(m, 0, sizeof(*m));
                /* Call statfs to get the real numbers */
                struct statfs linux_st;
                if (statfs(mp, &linux_st) == 0) {
                    m->f_bsize = linux_st.f_bsize;
                    m->f_iosize = linux_st.f_bsize;
                    m->f_blocks = linux_st.f_blocks;
                    m->f_bfree = linux_st.f_bfree;
                    m->f_bavail = linux_st.f_bavail;
                    m->f_files = linux_st.f_files;
                    m->f_ffree = linux_st.f_ffree;
                    memcpy(&m->f_fsid, &linux_st.f_fsid, sizeof(m->f_fsid));
                    m->f_type = linux_st.f_type;
                }
                strncpy(m->f_fstypename, fstype, sizeof(m->f_fstypename) - 1);
                strncpy(m->f_mntonname, mp, sizeof(m->f_mntonname) - 1);
                strncpy(m->f_mntfromname, dev, sizeof(m->f_mntfromname) - 1);
                mntcount++;
            }
        }
        fclose(f);
    }

    if (mntbufp) *mntbufp = mntbuf;
    return mntcount;
}

/* getmntinfo$INODE64 — same as getmntinfo (64-bit inode variant) */
int macify_getmntinfo_inode64(struct macos_statfs **mntbufp, int flags) __asm__("getmntinfo$INODE64");
int macify_getmntinfo_inode64(struct macos_statfs **mntbufp, int flags) {
    return macify_getmntinfo(mntbufp, flags);
}

/* ___assert_rtn — macOS assertion function.
 *
 * macOS's assert() calls ___assert_rtn with file, line, function,
 * expression. Map it to standard assert behavior.
 */

void __assert_rtn(const char *func, const char *file, int line, const char *expr) {
    fprintf(stderr, "Assertion failed: %s, function %s, file %s, line %d\n",
            expr, func, file, line);
    abort();
}

/* CommonCrypto — macOS's crypto framework. Rust uses CCRandomGenerateBytes
 * for random number generation. We implement it using the getrandom syscall
 * (faster than /dev/urandom, and doesn't require file descriptor). */
int CCRandomGenerateBytes(void *bytes, size_t count) {
    if (!bytes || count == 0) return -1;
    /* Use Linux's getrandom syscall directly */
    size_t got = 0;
    while (got < count) {
        long ret = syscall(318, (char *)bytes + got, count - got, 0);
        if (ret <= 0) {
            /* Fallback to /dev/urandom if getrandom fails */
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd < 0) return -1;
            while (got < count) {
                ssize_t n = read(fd, (char *)bytes + got, count - got);
                if (n <= 0) { close(fd); return -1; }
                got += n;
            }
            close(fd);
            return 0;
        }
        got += ret;
    }
    return 0;  /* kCCSuccess = 0 */
}

/* getentropy — macOS libc function (since macOS 10.12) that fills a buffer
 * with random bytes. OpenSSL's RNG uses this on macOS. On Linux, the
 * equivalent is the getrandom() syscall (number 318 on x86_64).
 * macOS limits getentropy to 256 bytes per call; we honor that limit. */
#include <sys/random.h>
int getentropy(void *buffer, size_t length) {
    if (!buffer) return -1;
    if (length > 256) {
        errno = 22;  /* EINVAL — macOS limit */
        return -1;
    }
    /* Use Linux's getrandom syscall (318) which doesn't require /dev/urandom */
    long ret = syscall(318, buffer, length, 0);
    if (ret < 0) {
        /* Fallback to /dev/urandom if getrandom fails */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
        size_t got = 0;
        while (got < length) {
            ssize_t n = read(fd, (char *)buffer + got, length - got);
            if (n <= 0) { close(fd); return -1; }
            got += n;
        }
        close(fd);
    }
    return 0;
}

/* SecRandomCopyBytes — Security framework's random number generator.
 * Same implementation as CCRandomGenerateBytes. */
int SecRandomCopyBytes(void *rnd, size_t count, void *bytes) {
    (void)rnd;
    return CCRandomGenerateBytes(bytes, count);
}

