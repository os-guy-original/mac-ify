/* regex.c — BSD-layout regex API over glibc's implementation.
 *
 * macOS regex_t is 32 bytes ({int magic; size_t nsub; const char *endp;
 * void *g}); glibc's is 64. A macOS binary hands us a 32-byte object and
 * glibc's regcomp memsets 64 bytes through it, smashing whatever follows.
 * We keep the real state in a heap wrapper and expose the BSD shape. */
#include "../shim.h"
#include <regex.h>

/* Offsets in the caller's macOS regex_t (per Apple regex.h) */
#define MACOS_RE_MAGIC  0   /* int */
#define MACOS_RE_NSUB   8   /* size_t */
#define MACOS_RE_ENDP   16  /* const char * */
#define MACOS_RE_G      24  /* void * */
#define MACOS_REGEX_T_SIZE 32

typedef struct {
    regex_t real;            /* glibc state (64 bytes) */
    uint32_t cookie;         /* sanity marker */
} macify_regex_wrapper;

#define MACIFY_REGEX_COOKIE 0x6D63724Bu /* 'mcrK' */

static int (*real_regcomp)(regex_t *, const char *, int) = NULL;
static int (*real_regexec)(const regex_t *, const char *, size_t,
                           regmatch_t[], int) = NULL;
static size_t (*real_regerror)(int, const regex_t *, char *, size_t) = NULL;
static void (*real_regfree)(regex_t *) = NULL;

static void resolve_real(void) {
    if (!real_regcomp) {
        real_regcomp = macify_elf_lookup("regcomp");
    }
    if (!real_regexec) real_regexec = macify_elf_lookup("regexec");
    if (!real_regerror) real_regerror = macify_elf_lookup("regerror");
    if (!real_regfree) real_regfree = macify_elf_lookup("regfree");
}

/* Bits POSIX defines identically on both systems; anything else (BSD
 * REG_PEND etc.) is stripped so glibc never sees foreign bits. */
#define REG_FLAGS_MASK (REG_EXTENDED | REG_ICASE | REG_NEWLINE | REG_NOSUB)

int macify_regcomp(void *preg, const char *pattern, int flags)
        __asm__("regcomp");
int macify_regcomp(void *preg, const char *pattern, int flags) {
    if (!preg || !pattern) return EINVAL;
    resolve_real();
    if (!real_regcomp || !real_regfree) return ENOSYS;

    macify_regex_wrapper *w = calloc(1, sizeof(*w));
    if (!w) return REG_ESPACE;
    w->cookie = MACIFY_REGEX_COOKIE;

    int rc = real_regcomp(&w->real, pattern, flags & REG_FLAGS_MASK);
    if (rc != 0) { free(w); return rc; }

    *(uint32_t *)((char *)preg + MACOS_RE_MAGIC) = 0x2002;  /* BSD re_magic */
    *(size_t *) ((char *)preg + MACOS_RE_NSUB)  = w->real.re_nsub;
    *(const char **)((char *)preg + MACOS_RE_ENDP) = NULL;
    *(void **)     ((char *)preg + MACOS_RE_G)  = w;
    return 0;
}

int macify_regexec(const void *preg, const char *string, size_t nmatch,
                   void *pmatch_v, int eflags) __asm__("regexec");
int macify_regexec(const void *preg, const char *string, size_t nmatch,
                   void *pmatch_v, int eflags) {
    if (!preg) return REG_NOERROR;
    resolve_real();
    const macify_regex_wrapper *w =
        *(macify_regex_wrapper *const *)((const char *)preg + MACOS_RE_G);
    if (!w || w->cookie != MACIFY_REGEX_COOKIE || !real_regexec)
        return REG_NOMATCH;
    regmatch_t *pm = (regmatch_t *)pmatch_v;
    if (!pmatch_v || nmatch == 0)
        return real_regexec(&w->real, string, nmatch, NULL, eflags & 0x3);
    /*
     * ABI translation: Darwin regoff_t is __off_t (8B on LP64) so the
     * caller's regmatch_t entries are 16 bytes {long,long}; glibc packs
     * two int32 into 8. Passing the caller's buffer to glibc half-fills
     * each slot — bash then reads the packed pair as one long and
     * memsets -(eo<<32) bytes ([[ =~ ]] heap corruption). Run glibc on
     * our own buffer and widen: entry i at [i*16], rm_so +0, rm_eo +8.
     */
    regmatch_t *tmp = (regmatch_t *)calloc(nmatch, sizeof(regmatch_t));
    if (!tmp) return REG_NOMATCH;
    int rc = real_regexec(&w->real, string, nmatch, tmp, eflags & 0x3);
    if (rc == 0) {
        long *out = (long *)pm;
        for (size_t i = 0; i < nmatch; i++) {
            out[2 * i]     = (long)tmp[i].rm_so;
            out[2 * i + 1] = (long)tmp[i].rm_eo;
        }
    }
    free(tmp);
    return rc;
}

size_t macify_regerror(int errcode, const void *preg, char *errbuf,
                       size_t errbuf_size) __asm__("regerror");
size_t macify_regerror(int errcode, const void *preg, char *errbuf,
                       size_t errbuf_size) {
    resolve_real();
    if (real_regerror) {
        const regex_t *real_preg = NULL;
        if (preg) {
            const macify_regex_wrapper *w =
                *(macify_regex_wrapper *const *)((const char *)preg + MACOS_RE_G);
            if (w && w->cookie == MACIFY_REGEX_COOKIE) real_preg = &w->real;
        }
        return real_regerror(errcode, real_preg, errbuf, errbuf_size);
    }
    const char *msg = "regex error";
    size_t n = strlen(msg) + 1;
    if (errbuf && errbuf_size) snprintf(errbuf, errbuf_size, "%s", msg);
    return n;
}

void macify_regfree(void *preg) __asm__("regfree");
void macify_regfree(void *preg) {
    if (!preg) return;
    resolve_real();
    macify_regex_wrapper *w =
        *(macify_regex_wrapper **)((char *)preg + MACOS_RE_G);
    if (!w || w->cookie != MACIFY_REGEX_COOKIE) return;
    if (real_regfree) real_regfree(&w->real);
    free(w);
    *(void **)((char *)preg + MACOS_RE_G) = NULL;
}
