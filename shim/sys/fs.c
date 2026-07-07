/* Split from misc.c */
#include "../shim.h"

/* File system stubs */
int getfsstat64(void *buf, int bufsize, int mode) {
    (void)buf; (void)bufsize; (void)mode;
    return 0;  /* no filesystems */
}

int unmount(const char *path, int flags) {
    (void)path; (void)flags;
    errno = ENOENT;
    return -1;
}

/* clonefile/copyfile — macOS file cloning. Not available on Linux. */
int clonefile(const char *src, const char *dst, int flags) {
    (void)src; (void)dst; (void)flags;
    errno = ENOSYS;
    return -1;
}
int clonefileat(int src_fd, const char *src, int dst_fd, const char *dst, int flags) {
    (void)src_fd; (void)src; (void)dst_fd; (void)dst; (void)flags;
    errno = ENOSYS;
    return -1;
}
int fclonefileat(int srcfd, int dstfd, const char *dst, int flags) {
    /* macOS clonefile copies file data by reference. On Linux, fall back
     * to a regular file copy. Return 0 on success so the caller thinks
     * the clone succeeded. */
    (void)flags;
    /* Read source file size */
    struct stat st;
    if (fstat(srcfd, &st) < 0) return -1;
    /* Open destination */
    int dst_fd = openat(dstfd, dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
    if (dst_fd < 0) return -1;
    /* Copy data */
    char buf[65536];
    ssize_t n;
    while ((n = read(srcfd, buf, sizeof(buf))) > 0) {
        ssize_t w = write(dst_fd, buf, n);
        if (w != n) { close(dst_fd); return -1; }
    }
    close(dst_fd);
    return 0;
}
int copyfile(const char *from, const char *to, void *state, int mode) {
    (void)from; (void)to; (void)state; (void)mode;
    errno = ENOSYS;
    return -1;
}
int fcopyfile(int from, int to, void *state, int mode) {
    (void)from; (void)to; (void)state; (void)mode;
    errno = ENOSYS;
    return -1;
}
void *copyfile_state_alloc(void) { return NULL; }
void copyfile_state_free(void *s) { (void)s; }
int copyfile_state_get(void *s, uint32_t flag, void *dst) {
    (void)s; (void)flag; (void)dst;
    return -1;
}
int copyfile_state_set(void *s, uint32_t flag, const void *src) {
    (void)s; (void)flag; (void)src;
    return -1;
}

/* renamex_np / renameatx_np — macOS extended rename. Map to rename/renameat.
 * CRITICAL: The `state` parameter and `flags` (e.g. RENAME_SWAP, RENAME_EXCL)
 * are macOS-specific. We ignore them and use plain rename.
 * The fd parameters may be AT_FDCWD (-100 on Linux). Handle that correctly. */
int renamex_np(const char *from, const char *to, unsigned int flags, void *state) {
    (void)flags; (void)state;
    return rename(from, to);
}
int renameatx_np(int fromfd, const char *from, int tofd, const char *to, unsigned int flags, void *state) {
    (void)flags; (void)state;
    /* macOS AT_FDCWD = -2, Linux AT_FDCWD = -100 */
    if (fromfd == -2) fromfd = -100;
    if (tofd == -2) tofd = -100;
    return renameat(fromfd, from, tofd, to);
}

/* Mach VM stubs */

/* ── ACL (Access Control List) stubs ────────────────────────────
 * macOS binaries (especially coreutils like `ls -l`) call these to
 * check for extended ACLs on files. Linux uses a different ACL API
 * (acl_get_fd, acl_get_file from libacl), but for simplicity we
 * stub these to report "no ACLs" — sufficient for `ls -l`. */

/* acl_t is opaque — we use void* */
typedef void *acl_t;
/* acl_entry_t is opaque */
typedef void *acl_entry_t;
/* acl_type_t is int */
typedef int acl_type_t;

/* ACL types on macOS */
#define MACOS_ACL_TYPE_EXTENDED     0x00000100
#define MACOS_ACL_TYPE_NFS4         0x00000002

/* acl_get_fd_np — get ACL by file descriptor.
 * Returns NULL on failure (no ACL), sets errno. */
acl_t acl_get_fd_np(int fd, acl_type_t type) {
    (void)fd; (void)type;
    errno = 2;  /* ENOENT — no ACL */
    return NULL;
}

/* acl_get_fd — alias without _np suffix. Return NULL (no ACL) but
 * don't set errno to a failure value — some binaries (mv, cp) abort
 * if acl_get_fd returns an error. */
acl_t acl_get_fd(int fd) {
    (void)fd;
    errno = 0;
    return NULL;
}

/* acl_get_file — get ACL by path. */
acl_t acl_get_file(const char *path, acl_type_t type) {
    (void)path; (void)type;
    errno = 2;  /* ENOENT — no ACL */
    return NULL;
}

/* acl_get_link_np — get ACL of symlink (without following). */
acl_t acl_get_link_np(const char *path, acl_type_t type) {
    (void)path; (void)type;
    errno = 2;  /* ENOENT — no ACL */
    return NULL;
}

/* acl_get_entry — get an ACL entry.
 * Returns 1 if entry found, 0 if no more entries, -1 on error. */
int acl_get_entry(acl_t acl, int entry_id, acl_entry_t *entry_p) {
    (void)acl; (void)entry_id;
    if (entry_p) *entry_p = NULL;
    return 0;  /* no entries */
}

/* acl_free — free ACL or returned buffer. */
int acl_free(void *obj) {
    (void)obj;
    return 0;
}

/* acl_valid — validate ACL. */
int acl_valid(acl_t acl) {
    (void)acl;
    return 0;
}

/* acl_to_text — convert ACL to text. */
char *acl_to_text(acl_t acl, ssize_t *len_p) {
    (void)acl;
    if (len_p) *len_p = 0;
    return NULL;
}

/* acl_from_text — convert text to ACL. */
acl_t acl_from_text(const char *buf) {
    (void)buf;
    return NULL;
}

/* acl_dup — duplicate ACL. */
acl_t acl_dup(acl_t acl) {
    (void)acl;
    return NULL;
}

/* acl_create_entry — create new ACL entry. */
int acl_create_entry(acl_t *acl_p, acl_entry_t *entry_p) {
    (void)acl_p; (void)entry_p;
    errno = 22;  /* EINVAL */
    return -1;
}

/* acl_set_fd_np — set ACL on file descriptor. */
int acl_set_fd_np(int fd, acl_t acl, acl_type_t type) {
    (void)fd; (void)acl; (void)type;
    errno = 22;  /* EINVAL */
    return -1;
}

/* acl_set_fd — alias without _np suffix. Always succeed (no-op). */
int acl_set_fd(int fd, acl_t acl) {
    (void)fd; (void)acl;
    return 0;
}

/* acl_set_file — set ACL on file by path. */
int acl_set_file(const char *path, acl_type_t type, acl_t acl) {
    (void)path; (void)type; (void)acl;
    errno = 22;  /* EINVAL */
    return -1;
}

/* acl_init — allocate empty ACL. */
acl_t acl_init(int count) {
    (void)count;
    return NULL;
}

/* ── strmode — BSD file mode to string conversion ───────────────
 * Used by `ls -l` to format the permissions string (e.g., "drwxr-xr-x").
 * macOS has this in libSystem; glibc doesn't. */

#include <sys/stat.h>

void strmode(int mode, char *bp) {
    /* Mode bits (same as BSD):
     * 0-8: rwxrwxrwx for user/group/other
     * 9-11: setuid/setgid/sticky
     * 12-15: file type */
    /* File type — uses the S_IFMT bits at top of mode */
    switch (mode & 0xF000) {
        case 0x1000: bp[0] = 'p'; break;  /* S_IFIFO  */
        case 0x2000: bp[0] = 'c'; break;  /* S_IFCHR  */
        case 0x4000: bp[0] = 'd'; break;  /* S_IFDIR  */
        case 0x6000: bp[0] = 'b'; break;  /* S_IFBLK  */
        case 0x8000: bp[0] = '-'; break;  /* S_IFREG  */
        case 0xA000: bp[0] = 'l'; break;  /* S_IFLNK  */
        case 0xC000: bp[0] = 's'; break;  /* S_IFSOCK */
        default:     bp[0] = '?'; break;
    }
    /* User permissions */
    bp[1] = (mode & 0400) ? 'r' : '-';
    bp[2] = (mode & 0200) ? 'w' : '-';
    if (mode & 04000) {
        bp[3] = (mode & 0100) ? 's' : 'S';
    } else {
        bp[3] = (mode & 0100) ? 'x' : '-';
    }
    /* Group permissions */
    bp[4] = (mode & 0040) ? 'r' : '-';
    bp[5] = (mode & 0020) ? 'w' : '-';
    if (mode & 02000) {
        bp[6] = (mode & 0010) ? 's' : 'S';
    } else {
        bp[6] = (mode & 0010) ? 'x' : '-';
    }
    /* Other permissions */
    bp[7] = (mode & 0004) ? 'r' : '-';
    bp[8] = (mode & 0002) ? 'w' : '-';
    if (mode & 01000) {
        bp[9] = (mode & 0001) ? 't' : 'T';
    } else {
        bp[9] = (mode & 0001) ? 'x' : '-';
    }
    bp[10] = ' ';
    bp[11] = '\0';
}
