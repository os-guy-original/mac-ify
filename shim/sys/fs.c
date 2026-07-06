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
    (void)srcfd; (void)dstfd; (void)dst; (void)flags;
    errno = ENOSYS;
    return -1;
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

/* renamex_np / renameatx_np — macOS extended rename. Map to rename/renameat. */
int renamex_np(const char *from, const char *to, unsigned int flags, void *state) {
    (void)flags; (void)state;
    return rename(from, to);
}
int renameatx_np(int fromfd, const char *from, int tofd, const char *to, unsigned int flags, void *state) {
    (void)flags; (void)state;
    return renameat(fromfd, from, tofd, to);
}

/* Mach VM stubs */
