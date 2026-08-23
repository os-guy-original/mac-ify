/* variants.c — macOS $-suffixed libc symbol aliases.
 *
 * Homebrew-built binaries import DARWIN_EXTSN and INODE64 symbol
 * variants (realpath$DARWIN_EXTSN, stat$INODE64, ...). Unbound, they
 * fall to the unresolved stub and callers turn the failure into empty
 * strings or silent breakage (observed: ruby File.realpath "" →
 * brew.rb dying at require_relative "global").
 *
 * Path-taking variants route through the translating hooks; everything
 * else passes straight to libc. */
#include "../shim.h"
#include <stdio.h>
#include <dirent.h>
#include <grp.h>
#include <sys/select.h>

/* Translating implementations live beside their plain-name hooks. */
extern char *macify_do_realpath(const char *, char *) __asm__("macify_do_realpath");
extern FILE *macify_do_fopen(const char *, const char *) __asm__("macify_do_fopen");

char *macify_realpath_extsn(const char *path, char *resolved)
        __asm__("realpath$DARWIN_EXTSN");
char *macify_realpath_extsn(const char *path, char *resolved) {
    return macify_do_realpath(path, resolved);
}

FILE *macify_fopen_extsn(const char *path, const char *mode)
        __asm__("fopen$DARWIN_EXTSN");
FILE *macify_fopen_extsn(const char *path, const char *mode) {
    return macify_do_fopen(path, mode);
}

FILE *macify_fdopen_extsn(int fd, const char *mode)
        __asm__("fdopen$DARWIN_EXTSN");
FILE *macify_fdopen_extsn(int fd, const char *mode) {
    static FILE *(*real)(int, const char *) = NULL;
    if (!real) real = macify_elf_lookup("fdopen");
    return real ? real(fd, mode) : NULL;
}

int macify_select_extsn(int nfds, fd_set *r, fd_set *w, fd_set *e,
                        struct timeval *tv) __asm__("select$DARWIN_EXTSN");
int macify_select_extsn(int nfds, fd_set *r, fd_set *w, fd_set *e,
                        struct timeval *tv) {
    static int (*real)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = NULL;
    if (!real) real = macify_elf_lookup("select");
    return real ? real(nfds, r, w, e, tv) : -1;
}

int macify_getgroups_extsn(int size, gid_t list[])
        __asm__("getgroups$DARWIN_EXTSN");
int macify_getgroups_extsn(int size, gid_t list[]) {
    static int (*real)(int, gid_t *) = NULL;
    if (!real) real = macify_elf_lookup("getgroups");
    return real ? real(size, list) : -1;
}

/* ── INODE64 directory variants: no path args after DIR* — passthrough ── */
DIR *macify_fdopendir_ino64(int fd) __asm__("fdopendir$INODE64");
DIR *macify_fdopendir_ino64(int fd) {
    static DIR *(*real)(int) = NULL;
    if (!real) real = macify_elf_lookup("fdopendir");
    return real ? real(fd) : NULL;
}

void macify_rewinddir_ino64(DIR *d) __asm__("rewinddir$INODE64");
void macify_rewinddir_ino64(DIR *d) {
    static void (*real)(DIR *) = NULL;
    if (!real) real = macify_elf_lookup("rewinddir");
    if (real) real(d);
}

long macify_telldir_ino64(DIR *d) __asm__("telldir$INODE64");
long macify_telldir_ino64(DIR *d) {
    static long (*real)(DIR *) = NULL;
    if (!real) real = macify_elf_lookup("telldir");
    return real ? real(d) : -1;
}

void macify_seekdir_ino64(DIR *d, long loc) __asm__("seekdir$INODE64");
void macify_seekdir_ino64(DIR *d, long loc) {
    static void (*real)(DIR *, long) = NULL;
    if (!real) real = macify_elf_lookup("seekdir");
    if (real) real(d, loc);
}
