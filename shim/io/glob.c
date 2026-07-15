/* glob.c — glob() translation shim
 *
 * macOS and Linux have DIFFERENT glob_t struct layouts:
 *
 *   macOS glob_t (size = 56 bytes on x86_64):
 *     size_t      gl_pathc;
 *     char      **gl_pathv;
 *     size_t      gl_offs;
 *     int         gl_flags;
 *     void      (*gl_closedir)(void *);
 *     dirent_t  *(*gl_readdir)(void *);
 *     void     *(*gl_opendir)(const char *);
 *     int       (*gl_lstat)(const char *, stat_t *);
 *     int       (*gl_stat)(const char *, stat_t *);
 *
 *   Linux glibc glob_t (size = 64 bytes on x86_64):
 *     size_t      gl_pathc;
 *     char      **gl_pathv;
 *     size_t      gl_offs;
 *     int         gl_flags;
 *     int       (*gl_errfunc)(const char *, int);  ← EXTRA FIELD
 *     void      (*gl_closedir)(void *);
 *     dirent_t  *(*gl_readdir)(void *);
 *     void     *(*gl_opendir)(const char *);
 *     int       (*gl_lstat)(const char *, stat_t *);
 *     int       (*gl_stat)(const char *, stat_t *);
 *
 * If a macOS binary allocates sizeof(macOS glob_t) = 56 bytes and passes
 * it to glibc's glob(), glibc writes 64 bytes — corrupting 8 bytes of
 * the caller's stack/heap. This causes random crashes (e.g. bash
 * segfaults in glob+0x1c89 after fork()/wait()).
 *
 * This shim translates the macOS glob_t to a Linux glob_t, calls
 * glibc's real glob(), then copies the result back to the macOS
 * struct.
 */

#include "io_internal.h"
#include <glob.h>

/* macOS glob_t — matches the layout macOS binaries expect. */
struct macos_glob_t {
    size_t      gl_pathc;
    char      **gl_pathv;
    size_t      gl_offs;
    int         gl_flags;
    void      (*gl_closedir)(void *);
    struct dirent *(*gl_readdir)(void *);
    void     *(*gl_opendir)(const char *);
    int       (*gl_lstat)(const char *, void *);
    int       (*gl_stat)(const char *, void *);
};

/* macOS glob() flags (from <glob.h> on macOS) — same values as Linux
 * for the common flags, but include them here for completeness. */
#define MACOS_GLOB_APPEND      0x0001
#define MACOS_GLOB_DOOFFS      0x0002
#define MACOS_GLOB_ERR         0x0004
#define MACOS_GLOB_MARK        0x0008
#define MACOS_GLOB_NOCHECK     0x0010
#define MACOS_GLOB_NOSORT      0x0020
#define MACOS_GLOB_NOESCAPE    0x0040
#define MACOS_GLOB_PERIOD      0x0080
#define MACOS_GLOB_TILDE       0x0800
#define MACOS_GLOB_TILDE_CHECK 0x4000
/* GLOB_BRACE, GLOB_NOMAGIC, GLOB_QUOTE, GLOB_LIMIT, etc. are macOS-only
 * extensions. We pass them through but glibc will ignore them. */

/* glob — translate macOS glob_t to Linux glob_t, call real glob,
 * translate result back. */
int macify_glob(const char *pattern, int flags,
                int (*errfunc)(const char *, int),
                struct macos_glob_t *macos_pglob) __asm__("glob");
int macify_glob(const char *pattern, int flags,
                int (*errfunc)(const char *, int),
                struct macos_glob_t *macos_pglob) {
    static int (*real_glob)(const char *, int,
                            int (*)(const char *, int),
                            glob_t *) = NULL;
    if (!real_glob) real_glob = macify_elf_lookup("glob");

    if (!macos_pglob) {
        /* No output struct — just call real glob with NULL.
         * This shouldn't happen but be defensive. */
        return real_glob(pattern, flags, errfunc, NULL);
    }

    /* Translate macOS flags to Linux flags.
     * Most are the same; macOS-only flags are masked out. */
    int linux_flags = 0;
    if (flags & MACOS_GLOB_APPEND)      linux_flags |= GLOB_APPEND;
    if (flags & MACOS_GLOB_DOOFFS)      linux_flags |= GLOB_DOOFFS;
    if (flags & MACOS_GLOB_ERR)         linux_flags |= GLOB_ERR;
    if (flags & MACOS_GLOB_MARK)        linux_flags |= GLOB_MARK;
    if (flags & MACOS_GLOB_NOCHECK)     linux_flags |= GLOB_NOCHECK;
    if (flags & MACOS_GLOB_NOSORT)      linux_flags |= GLOB_NOSORT;
    if (flags & MACOS_GLOB_NOESCAPE)    linux_flags |= GLOB_NOESCAPE;
    if (flags & MACOS_GLOB_PERIOD)      linux_flags |= GLOB_PERIOD;
    if (flags & MACOS_GLOB_TILDE)       linux_flags |= GLOB_TILDE;
    if (flags & MACOS_GLOB_TILDE_CHECK) linux_flags |= GLOB_TILDE_CHECK;

    /* Build a Linux glob_t from the macOS one.
     * Linux has the extra gl_errfunc field; we use the errfunc parameter. */
    glob_t linux_pglob;
    memset(&linux_pglob, 0, sizeof(linux_pglob));
    linux_pglob.gl_offs = macos_pglob->gl_offs;
    linux_pglob.gl_flags = macos_pglob->gl_flags;
    /* gl_pathc and gl_pathv start at 0/NULL; glob will fill them in. */
    /* We do NOT pass macos's gl_closedir/readdir/opendir/lstat/stat
     * callbacks to Linux's glob — they have macOS struct types and
     * would crash. Let glibc use its own defaults. */

    int ret = real_glob(pattern, linux_flags, errfunc, &linux_pglob);
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: glob(\"%s\", 0x%x->0x%x) = %d gl_pathc=%zu\n",
            pattern ? pattern : "(null)", flags, linux_flags, ret,
            linux_pglob.gl_pathc);
        (void)write(2, b, n);
    }

    /* Copy results back to macOS glob_t */
    macos_pglob->gl_pathc = linux_pglob.gl_pathc;
    macos_pglob->gl_pathv = linux_pglob.gl_pathv;
    macos_pglob->gl_flags = linux_pglob.gl_flags;
    /* gl_offs is input-only on macOS — don't overwrite. */

    return ret;
}

/* globfree — free paths allocated by glob. */
void macify_globfree(struct macos_glob_t *macos_pglob) __asm__("globfree");
void macify_globfree(struct macos_glob_t *macos_pglob) {
    static void (*real_globfree)(glob_t *) = NULL;
    if (!real_globfree) real_globfree = macify_elf_lookup("globfree");
    if (!macos_pglob || !macos_pglob->gl_pathv) return;

    /* Build a Linux glob_t with just the gl_pathv to free it.
     * glibc's globfree only reads gl_pathc and gl_pathv (and gl_flags
     * to check GLOB_MALLOC), so this is safe. */
    glob_t linux_pglob;
    memset(&linux_pglob, 0, sizeof(linux_pglob));
    linux_pglob.gl_pathc = macos_pglob->gl_pathc;
    linux_pglob.gl_pathv = macos_pglob->gl_pathv;
    linux_pglob.gl_flags = macos_pglob->gl_flags;

    real_globfree(&linux_pglob);

    /* Clear the macOS struct so a double-free is safe. */
    macos_pglob->gl_pathc = 0;
    macos_pglob->gl_pathv = NULL;
}

/* glob64 — same as glob on 64-bit systems. Just forward. */
int macify_glob64(const char *pattern, int flags,
                  int (*errfunc)(const char *, int),
                  struct macos_glob_t *macos_pglob) __asm__("glob64");
int macify_glob64(const char *pattern, int flags,
                  int (*errfunc)(const char *, int),
                  struct macos_glob_t *macos_pglob) {
    return macify_glob(pattern, flags, errfunc, macos_pglob);
}
