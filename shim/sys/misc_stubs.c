#include <malloc.h>
/* misc_stubs.c - remaining small stubs from misc.c */
#include "../shim.h"

/* kCFTypeArrayCallBacks - a static struct that CoreFoundation uses for
 * CFArray creation. We provide a zeroed struct (all NULL callbacks). */
static const char kCFTypeArrayCallBacks_data[64] = {0};  /* 8 function pointers */
const void *kCFTypeArrayCallBacks = kCFTypeArrayCallBacks_data;

/* Additional CF stubs needed by curl */
void *CFErrorCopyDescription(void *err) {
    (void)err;
    return NULL;
}
long CFErrorGetCode(void *err) {
    (void)err;
    return 0;
}

/* Security framework TLS stubs - curl uses these for certificate validation.
 * We stub them to allow curl to fall back to no certificate verification. */
void *SecCertificateCreateWithData(void *alloc, void *data) {
    (void)alloc; (void)data;
    return NULL;
}
void *SecPolicyCreateRevocation(unsigned long revocationFlags) {
    (void)revocationFlags;
    return NULL;
}
void *SecPolicyCreateSSL(int server, void *hostname) {
    (void)server; (void)hostname;
    return NULL;
}
int SecTrustCreateWithCertificates(void *certs, void *policies, void **trust) {
    (void)certs; (void)policies;
    if (trust) *trust = NULL;
    return -1;  /* errSecParam */
}
int SecTrustEvaluateWithError(void *trust, void *error) {
    (void)trust; (void)error;
    return 0;  /* success - trust everything */
}
int SecTrustSetOCSPResponse(void *trust, void *response) {
    (void)trust; (void)response;
    return 0;
}

/* CoreServices framework stubs - nvim and other binaries reference these. */

/* LocaleRefGetPartString - gets a locale string part (language, country, etc.)
 * Signature: OSStatus LocaleRefGetPartString(LocaleRef loc, LocalePartCode partCode,
 *              Boolean wantVerbatim, ByteCount maxStringLen, char *resultString)
 * We return "en" / "US" / "en_US" for the common parts. */
int LocaleRefGetPartString(int loc, int partCode, int wantVerbatim,
                           unsigned int maxStringLen, char *resultString) {
    if (!resultString || maxStringLen == 0) return -50;  /* paramErr */
    switch (partCode) {
        case 0:  /* language */
            strncpy(resultString, "en", maxStringLen);
            break;
        case 1:  /* country */
            strncpy(resultString, "US", maxStringLen);
            break;
        default:
            strncpy(resultString, "en_US", maxStringLen);
            break;
    }
    return 0;  /* noErr */
}

/* Objective-C Block runtime stubs --------------------------
 * macOS uses blocks (^{}), which are implemented via _NSConcreteGlobalBlock
 * and _NSConcreteStackBlock class objects. Binaries that use blocks (like
 * starship, written in Rust but using macOS APIs) reference these as
 * global symbols. We provide sentinel values - the actual block runtime
 * isn't needed for most CLI tools. */
static char ns_block_global_sentinel[64] = {0};
static char ns_block_stack_sentinel[64] = {0};
void *_NSConcreteGlobalBlock = ns_block_global_sentinel;
void *_NSConcreteStackBlock = ns_block_stack_sentinel;
void *_NSConcreteMallocBlock = ns_block_stack_sentinel;
void *_NSConcreteAutoBlock = ns_block_stack_sentinel;
void *_NSConcreteFinalizingBlock = ns_block_stack_sentinel;
void *_NSConcreteWeakBlockVariable = ns_block_stack_sentinel;

/* DWARF exception frame registration ----------------------
 * __register_frame / __deregister_frame are from libgcc, used for
 * DWARF-based exception handling. On macOS these are in libSystem.
 * On Linux, glibc provides them in libgcc_s. We provide no-op stubs
 * since our translated binaries handle exceptions differently. */
void __register_frame(const void *begin) { (void)begin; }
void __deregister_frame(const void *begin) { (void)begin; }

/* _dispatch_main_q - GCD (Grand Central Dispatch) main queue global.
 * starship and other Rust binaries reference this. We provide a sentinel. */
static char dispatch_main_q_sentinel[64] = {0};
void *_dispatch_main_q = dispatch_main_q_sentinel;

/* mach_continuous_time - returns continuous monotonic time in nanoseconds.
 * Like mach_absolute_time but doesn't reset on sleep. */
unsigned long long mach_continuous_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* notify_* - macOS notification system. Stub to no-op. */
int notify_register_file_descriptor(const char *name, int *fd, int flags, int *token) {
    (void)name; (void)flags;
    if (fd) *fd = -1;
    if (token) *token = 0;
    return 0;
}
int notify_cancel(int token) {
    (void)token;
    return 0;
}

/* ___mb_cur_max_l - macOS locale-specific multibyte character max length.
 * Return 1 (single-byte locale). */
int ___mb_cur_max_l(void *loc) {
    (void)loc;
    return 1;
}

/* ___mb_cur_max - macOS global multibyte character max length.
 * Used by wget's stdio macros. Return 1 (single-byte locale). */
int ___mb_cur_max(void) {
    return 1;
}

/* __mb_cur_max - alternate symbol name (some binaries use this). */
int __mb_cur_max(void) {
    return 1;
}

/* getprogname - macOS function to get the program name.
 * Returns __progname which we provide in shim_core.c. */
const char *getprogname(void) {
    extern char *__progname;
    return __progname ? __progname : "macify-app";
}

/* fpurge - macOS/BSD function to discard pending data in a stream's buffer.
 * glibc has __fpurge (note the leading underscore). We map fpurge to it. */
#include <stdio_ext.h>
int fpurge(FILE *stream) {
    if (stream) __fpurge(stream);
    return 0;
}

/* libiconv - macOS uses GNU libiconv as a separate library with `libiconv`
 * prefixed function names. glibc has iconv built-in (without prefix).
 * We provide the libiconv_-prefixed wrappers that delegate to glibc's iconv. */
#include <iconv.h>
typedef void *iconv_t_libiconv;
iconv_t_libiconv libiconv_open(const char *tocode, const char *fromcode) {
    return (iconv_t_libiconv)iconv_open(tocode, fromcode);
}
int libiconv_close(iconv_t_libiconv cd) {
    return iconv_close((iconv_t)cd);
}
size_t libiconv(iconv_t_libiconv cd, char **inbuf, size_t *inbytesleft,
                char **outbuf, size_t *outbytesleft) {
    return iconv((iconv_t)cd, inbuf, inbytesleft, outbuf, outbytesleft);
}

/* libintl - macOS uses GNU gettext as a separate library with `libintl`
 * prefixed function names. glibc has gettext built-in (without prefix).
 * We provide stubs that delegate to glibc or return no-op results. */
char *libintl_gettext(const char *msgid) {
    return (char *)msgid;  /* no translation - return original */
}
char *libintl_dgettext(const char *domainname, const char *msgid) {
    (void)domainname;
    return (char *)msgid;
}
char *libintl_ngettext(const char *msgid1, const char *msgid2, unsigned long n) {
    return (n == 1) ? (char *)msgid1 : (char *)msgid2;
}
char *libintl_bindtextdomain(const char *domainname, const char *dirname) {
    (void)domainname; (void)dirname;
    return (char *)domainname;
}
char *libintl_textdomain(const char *domainname) {
    return (char *)domainname;
}
/* libintl_setlocale - glibc has setlocale, delegate to it. */
#include <locale.h>
char *libintl_setlocale(int category, const char *locale) {
    /* Call our setlocale shim (not glibc's) to force LC_NUMERIC=C. */
    extern char *macify_setlocale(int, const char *) __asm__("setlocale");
    return macify_setlocale(category, locale);
}

/* setlocale - intercept and force LC_NUMERIC to "C" after any setlocale
 * call. macOS binaries call setlocale(LC_ALL, "") which sets all locale
 * categories based on environment. If LC_NUMERIC is set to a locale with
 * "," as decimal point, glibc's strtold loops infinitely (sort -n).
 * By forcing LC_NUMERIC=C, we ensure "." is always the decimal point. */
char *macify_setlocale(int category, const char *locale) __asm__("setlocale");
char *macify_setlocale(int category, const char *locale) {
    static char *(*real_setlocale)(int, const char *) = NULL;
    if (!real_setlocale) real_setlocale = dlsym(RTLD_NEXT, "setlocale");
    char *r = real_setlocale ? real_setlocale(category, locale) : NULL;
    if (r && real_setlocale) {
        /* Force LC_NUMERIC=C (prevents strtold loops with "," decimal point)
         * and LC_CTYPE=C (prevents character classification issues with
         * UTF-8 locale that cause sort -n to crash via inlined getc). */
        real_setlocale(LC_NUMERIC, "C");
        real_setlocale(LC_CTYPE, "C");
    }
    if (getenv("MACIFY_TRACE_LOCALE")) {
        char b[256];
        int n = snprintf(b, sizeof(b),
            "macify: setlocale(cat=%d, locale=%s) = %s, LC_NUMERIC forced to C\n",
            category, locale ? locale : "(null)", r ? r : "(null)");
        (void)write(2, b, n);
    }
    return r;
}

/* nl_langinfo - macOS function to query locale information.
 * tree uses nl_langinfo(CODESET) to check if the terminal supports UTF-8.
 * If it returns "ANSI_X3.4-1968" (ASCII), tree escapes non-ASCII filenames
 * as octal. We delegate to glibc's nl_langinfo.
 * IMPORTANT: macOS nl_item constants are different from glibc's.
 * macOS uses small integers (0-50), glibc uses large values (65536+)
 * with category bits in high bytes. Without translation, glibc segfaults
 * on macOS values (e.g., ls -l calling nl_langinfo(ABMON_1+month) crashes). */
#include <langinfo.h>

/* Translate macOS nl_item to glibc nl_item.
 * macOS layout (verified by disassembling ls_macos which pre-fetches
 * nl_langinfo(33..44) for months Jan..Dec - so macOS ABMON_1=33, not 32):
 *   CODESET=0, D_T_FMT=1, D_FMT=2, T_FMT=3, AM_STR=4, PM_STR=5,
 *   DAY_1..7=6..12, ABDAY_1..7=13..19, MON_1..12=21..32,
 *   ABMON_1..12=33..44, ERA=45, ERA_D_FMT=46, ERA_D_T_FMT=47,
 *   ERA_T_FMT=48, ALT_DIGITS=49, RADIXCHAR=50, THOUSEP=51,
 *   YESEXPR=52, NOEXPR=53, CRNCYSTR=54, D_MD_ORDER=55 */
static int macos_to_linux_nl_item(int macos_item) {
    switch (macos_item) {
        case 0:  return CODESET;            /* CODESET */
        case 1:  return D_T_FMT;
        case 2:  return D_FMT;
        case 3:  return T_FMT;
        case 4:  return AM_STR;
        case 5:  return PM_STR;
        case 50: return RADIXCHAR;
        case 51: return THOUSEP;
        case 52: return YESEXPR;
        case 53: return NOEXPR;
        case 54: return CRNCYSTR;
    }
    if (macos_item >= 6 && macos_item <= 12)
        return DAY_1 + (macos_item - 6);
    if (macos_item >= 13 && macos_item <= 19)
        return ABDAY_1 + (macos_item - 13);
    if (macos_item >= 21 && macos_item <= 32)
        return MON_1 + (macos_item - 21);
    if (macos_item >= 33 && macos_item <= 44)
        return ABMON_1 + (macos_item - 33);
    /* Unknown - return CODESET as safe fallback */
    return CODESET;
}

char *nl_langinfo(int item) {
    static char *(*real_nl_langinfo)(int) = NULL;
    if (!real_nl_langinfo) real_nl_langinfo = dlsym(RTLD_NEXT, "nl_langinfo");
    /* If item is in macOS range (small int), translate to glibc value. */
    if (item >= 0 && item < 100) {
        /* Force RADIXCHAR (macOS item 50) to always return "." regardless
         * of locale. sort -n uses strtold which reads nl_langinfo(RADIXCHAR)
         * for the decimal point. If it returns "," (comma) instead of ".",
         * strtold loops infinitely or crashes. */
        if (item == 50) return ".";
        if (item == 51) return "";  /* THOUSEP — no thousands separator */
        item = macos_to_linux_nl_item(item);
    }
    if (!real_nl_langinfo) return "ANSI_X3.4-1968";  /* ASCII fallback */
    return real_nl_langinfo(item);
}

/* px_proxy_factory_* - libproxy. Not available on this system. Stub them
 * so wget can run without proxy auto-detection. wget falls back to
 * environment variables (http_proxy, https_proxy) for proxy config. */
void *px_proxy_factory_new(void) {
    return NULL;  /* no proxy factory */
}
void px_proxy_factory_free(void *factory) {
    (void)factory;
}
char **px_proxy_factory_get_proxies(void *factory, const char *url) {
    (void)factory; (void)url;
    /* Return a NULL-terminated array with one NULL entry (no proxies). */
    char **result = (char **)calloc(1, sizeof(char *));
    return result;  /* caller frees the array but not the strings */
}
void px_proxy_factory_free_proxies(char **proxies) {
    if (proxies) free(proxies);
}

/* sigsetjmp - macOS uses sigsetjmp directly. glibc has __sigsetjmp (internal)
 * and sigsetjmp as a macro that calls __sigsetjmp. We need to undef the
 * macro to actually create a sigsetjmp symbol. */
#include <setjmp.h>
#undef sigsetjmp
extern int __sigsetjmp(sigjmp_buf env, int savesigs);
int sigsetjmp(sigjmp_buf env, int savesigs) __asm__("sigsetjmp");
int sigsetjmp(sigjmp_buf env, int savesigs) {
    return __sigsetjmp(env, savesigs);
}

/* ___darwin_check_fd_set_overflow - macOS fd_set overflow checker.
 * Note: macOS symbol has TWO leading underscores (__darwin_), but after
 * stripping one it becomes _darwin_ → we need to export "darwin_check_fd_set_overflow".
 * Actually the macOS symbol is ___darwin_check_fd_set_overflow (3 underscores).
 * After stripping one: __darwin_check_fd_set_overflow (2 underscores).
 * We need to export this name.
 *
 * Modern macOS SDKs compile FD_SET as:
 *   #define __DARWIN_FD_SET(n, p) \
 *       __darwin_check_fd_set_overflow((n), (p), 1) ? __darwin_fd_set((n), (p)) : 0
 * So this function MUST return non-zero (true) when the fd is safe to set
 * (i.e. fd < FD_SETSIZE). Returning 0 (or void, which leaves eax as
 * garbage - usually 0) causes FD_SET to silently skip setting the bit,
 * leaving the fd_set empty. select() then has nothing to wait on and
 * blocks until its timeout - exactly the "HTTPS hangs forever" symptom
 * seen in wget (which uses select() to wait for the TLS socket).
 *
 * The macOS implementation also emits an abort/warning when fd >=
 * FD_SETSIZE and silent==0; we just silently return 0 in that case. */
int __darwin_check_fd_set_overflow(int fd, const void *fdset, int silent) {
    (void)fdset;
    (void)silent;
    /* FD_SETSIZE = 1024 on both macOS and Linux. Return 1 (safe) for any
     * fd in [0, 1024), 0 (overflow) otherwise. */
    return (fd >= 0 && fd < 1024) ? 1 : 0;
}

/* __longjmp / __setjmp - macOS uses these instead of longjmp/setjmp.
 * Map to glibc's longjmp/setjmp. */
#include <setjmp.h>
void __longjmp(jmp_buf env, int val) { longjmp(env, val); }
int __setjmp(jmp_buf env) { return setjmp(env); }

/* ___strncpy_chk - fortified strncpy */
char *___strncpy_chk(char *dst, const char *src, size_t n, size_t dstlen) {
    (void)dstlen;
    return strncpy(dst, src, n);
}

/* ___cxa_atexit - C++ atexit handler. Map to atexit. */
int ___cxa_atexit(void (*fn)(void *), void *arg, void *dso) {
    (void)dso;
    /* We can't perfectly map cxa_atexit (which takes an arg) to atexit.
     * For simplicity, just call atexit with a wrapper if arg is NULL. */
    if (arg == NULL) {
        atexit((void (*)(void))fn);
    }
    return 0;
}

/* memset_s - C11 memset with guaranteed no elision. Just call memset. */
int memset_s(void *s, size_t smax, int c, size_t n) {
    if (s && n > 0) memset(s, c, n < smax ? n : smax);
    return 0;
}

/* arc4random_buf - fill buffer with random bytes (already defined above) */

/* connectx - macOS extended connect(). We implement it by translating
 * the macOS sockaddr_endpoints to a regular connect() call. */
struct macos_sa_endpoints {
    uint32_t sae_srclen;        /* offset 0 */
    const void *sae_srcaddr;    /* offset 8 */
    uint32_t sae_dstlen;        /* offset 16 */
    const void *sae_dstaddr;    /* offset 24 */
};

int connectx(int socket, const void *endpoints, unsigned int endpointslen,
             unsigned int ifscope, unsigned int flags, void *connid,
             unsigned int *connidlen, void *src, void *dst, void *dstlen) {
    (void)endpointslen; (void)ifscope; (void)flags; (void)connid;
    (void)connidlen; (void)src; (void)dst; (void)dstlen;

    /* Extract destination sockaddr from the sa_endpoints struct */
    const struct macos_sa_endpoints *ep = (const struct macos_sa_endpoints *)endpoints;
    if (!ep || !ep->sae_dstaddr || ep->sae_dstlen < 2) {
        errno = 22;  /* EINVAL */
        return -1;
    }

    /* Delegate to our connect() override which handles sockaddr translation.
     * connect() is exported via __asm__("connect") in shim_io.c. We use
     * a function pointer to avoid conflicting with glibc's connect declaration. */
    extern int macify_connect(int sockfd, const void *addr, socklen_t addrlen)
        __asm__("connect");
    return macify_connect(socket, ep->sae_dstaddr, ep->sae_dstlen);
}

/* CFTimeZoneResetSystem is now defined in misc/cf.c */



/* kqueue / kevent - macOS kernel event system. No Linux equivalent.
 *
 * Go's runtime on darwin uses kqueue for network polling (netpoll).
 * If kqueue() fails, Go throws "runtime: netpollinit failed" and aborts.
 *
 *
 * OpenSSL's async API uses these. We return 0 (success) from getcontext
 * and makecontext so OpenSSL's async init doesn't fail. The async API
 * won't actually work (contexts are invalid), but SSL_CTX_new succeeds
 */
/* OpenSSL OSSL_LIB_CTX functions -------------------------------
 * REMOVED: Previously we provided stub implementations of OSSL_LIB_CTX_new,
 * OSSL_LIB_CTX_free, OPENSSL_init_crypto, OPENSSL_init_ssl, etc.
 *
 * These stubs were HARMFUL: resolve_symbol() checks the shim first, so
 * our stubs were called INSTEAD of the real ones from libcrypto.so.3 /
 * libssl.so.3. This meant OpenSSL's default provider was never loaded
 * and cipher tables were never initialized, causing TLS handshake
 * failures ("illegal parameter" alert after Server Hello).
 *
 * The macOS curl binary dynamically links against libssl.3.dylib /
 * libcrypto.3.dylib, which our loader maps to libssl.so.3 /
 * libcrypto.so.3. By NOT providing these symbols in the shim,
 * resolve_symbol() finds the real implementations from the loaded
 * libssl.so.3 / libcrypto.so.3 libraries (via the extra handle
 * mechanism), ensuring proper OpenSSL initialization.
 *
 * If a macOS binary uses OpenSSL but libcrypto.so.3 / libssl.so.3 are
 * not available on the system, the binary will fail to load — which
 * is the correct behavior (better than silently using stubs that
 * return success without doing anything). */

/* proc_* functions are implemented in shim_mach.c with real /proc reading */

/* __slbsearch - macOS's bsearch variant (secure). Map to bsearch. */

void *__slbsearch(const void *key, const void *base, size_t nel, size_t width,
                  int (*compar)(const void *, const void *)) {
    return bsearch(key, base, nel, width, compar);
}

/* arc4random / arc4random_uniform - macOS random functions. */

uint32_t arc4random(void) {
    return (uint32_t)random();
}

uint32_t arc4random_uniform(uint32_t upper_bound) {
    if (upper_bound == 0) return 0;
    return arc4random() % upper_bound;
}

void arc4random_buf(void *buf, size_t nbytes) {
    /* Use /dev/urandom */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(buf, 1, nbytes, f) != nbytes) {
            /* Fall back to random() */
            uint8_t *p = (uint8_t *)buf;
            for (size_t i = 0; i < nbytes; i++) {
                p[i] = (uint8_t)random();
            }
        }
        fclose(f);
    } else {
        uint8_t *p = (uint8_t *)buf;
        for (size_t i = 0; i < nbytes; i++) {
            p[i] = (uint8_t)random();
        }
    }
}

/* _NSLog / _CFLog - logging stubs. */

void NSLog(void *format, ...) {
    (void)format;
    fprintf(stderr, "[NSLog called]\n");
}

void CFLog(int level, void *format, ...) {
    (void)level; (void)format;
    fprintf(stderr, "[CFLog called]\n");
}

/* macOS math function aliases.
 */
#include <math.h>
double __expm1(double x) { return expm1(x); }
double __log1p(double x) { return log1p(x); }
double __hypot(double x, double y) { return hypot(x, y); }
double __log2(double x) { return log2(x); }
double __logb(double x) { return logb(x); }
double __cbrt(double x) { return cbrt(x); }
double __atan2(double y, double x) { return atan2(y, x); }
double __pow(double x, double y) { return pow(x, y); }

/* __maskrune -- macOS character classification.
 *
 * Returns the runetype flags for character `ch` ANDed with `mask`.
 * Used by isalpha(), isdigit(), etc. on macOS.
 */

/* Functions that glibc inlines but macOS exports as dynamic symbols.
 * glibc only exports __cxa_atexit, not atexit. macOS binaries
 * reference atexit directly via the GOT.
 */
extern int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);

static void atexit_wrapper(void *arg) {
    void (*func)(void) = (void (*)(void))arg;
    /* Clear macOS __SERR bit at stdout offset 0x10 before calling
     * atexit handlers (e.g., close_stdout). This prevents false
     * "write error" reports caused by glibc's _IO_read_end pointer
     * having bit 0x40 set in its low byte. */
    extern FILE *__stdoutp;
    if (__stdoutp) {
        unsigned char *p = (unsigned char *)__stdoutp + 0x10;
        if (getenv("MACIFY_TRACE_ATEXIT")) {
            char b[128];
            int n = snprintf(b, sizeof(b), "macify: atexit_wrapper clearing bit 0x40 at %p+0x10 (was 0x%02x)\n", __stdoutp, *p);
            (void)write(2, b, n);
        }
        *p &= ~0x40;
    }
    func();
}

int atexit(void (*func)(void)) {
    return __cxa_atexit(atexit_wrapper, (void *)func, NULL);
}

/* exit: glibc inlines this. macOS exit() flushes stdio buffers and
 * calls atexit handlers before _exit(). Our shim must do the same.
 *
 * CRITICAL: We must run atexit handlers (glibc's __cxa_atexit chain)
 * so things like macify_print_ret_globals (registered via atexit by
 * shim_pthread.c) actually fire. The macify loader's post_main_cleanup
 * bypasses atexit by calling _exit directly, but if curl invokes
 * exit() from libSystem, we catch it here. */
void macify_print_ret_globals(void);  /* defined in shim_pthread.c */
void exit(int status) {
    /* Flush macOS FILE buffers before exiting */
    extern void macify_flush_macos_files(void);
    macify_flush_macos_files();
    fflush(NULL);  /* Flush all glibc stdio streams */
    _exit(status);
}

/* _exit — raw system exit. macOS binaries call _exit when they want to
 * exit immediately without flushing stdio. We must NOT resolve _exit to
 * exit() — that would cause double-flushing and incorrect behavior.
 * Export _exit so chained fixups find it directly instead of finding exit(). */
void _exit(int status) {
    syscall(231, status);  /* SYS_exit_group */
    __builtin_unreachable();
}
/* macOS asprintf (glibc may not export it on all versions). */
#include <stdarg.h>
int __asprintf(char **str, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(str, fmt, ap);
    va_end(ap);
    return ret;
}

/* macOS time functions. */
#include <time.h>
int __gmtime_r(const time_t *timep, struct tm *result) {
    return gmtime_r(timep, result) != NULL ? 0 : -1;
}
int __localtime_r(const time_t *timep, struct tm *result) {
    return localtime_r(timep, result) != NULL ? 0 : -1;
}



/* macOS malloc zone API (sqlite3 uses these) -- */

/* IMPORTANT: this struct must match the macOS _malloc_zone_t layout exactly,
 * because native macOS binaries compute offsets into it directly (e.g. they
 * call *(zone + 0x10) for the `size` method).  Apple's struct layout
 * (from mach/malloc.h) is:
 *   0x00  reserved1, reserved2
 *   0x10  size(zone, ptr)
 *   0x18  malloc(zone, size)
 *   0x20  calloc(zone, n, size)
 *   0x28  valloc(zone, size)
 *   0x30  free(zone, ptr)
 *   0x38  realloc(zone, ptr, size)
 *   0x40  destroy(zone)
 *   0x48  zone_name
 *   0x50  batch_malloc (unsigned), batch_free (unsigned)
 *   0x58  introspect
 *   0x60  reserved5, reserved6, reserved7
 *
 * The previous layout put `malloc` at offset 0x10, which caused sqlite3's
 * sqlite3MemSize to call our `malloc(zone, ptr_as_size)` instead of `size(zone, ptr)`,
 * allocating a huge buffer, returning NULL, and triggering a divide-by-zero
 * in sqlite3HashInsert. */
struct _malloc_zone_t {
    void *reserved1, *reserved2;                                            /* 0x00 */
    size_t (*size)(struct _malloc_zone_t *, const void *);                   /* 0x10 */
    void *(*malloc)(struct _malloc_zone_t *, size_t);                        /* 0x18 */
    void *(*calloc)(struct _malloc_zone_t *, size_t, size_t);                /* 0x20 */
    void *(*valloc)(struct _malloc_zone_t *, size_t);                        /* 0x28 */
    void  (*free)(struct _malloc_zone_t *, void *);                          /* 0x30 */
    void *(*realloc)(struct _malloc_zone_t *, void *, size_t);               /* 0x38 */
    void  (*destroy)(struct _malloc_zone_t *);                               /* 0x40 */
    const char *zone_name;                                                   /* 0x48 */
    unsigned batch_malloc, batch_free;                                       /* 0x50 */
    void *introspect;                                                        /* 0x58 */
    void *reserved5, *reserved6, *reserved7;                                 /* 0x60 */
    /* Pad to match macOS struct size (~256 bytes) */
    char _pad[128];
};

static size_t zs(struct _malloc_zone_t *z, const void *p) {
    (void)z;
    if (!p) return 0;
    return malloc_usable_size((void *)p);
}
static void *zm(struct _malloc_zone_t *z, size_t s) { (void)z; return malloc(s); }
static void *zc(struct _malloc_zone_t *z, size_t n, size_t s) { (void)z; return calloc(n, s); }
static void *zv(struct _malloc_zone_t *z, size_t s) { (void)z; return malloc(s); }
static void  zf(struct _malloc_zone_t *z, void *p) { (void)z; free(p); }
static void *zr(struct _malloc_zone_t *z, void *p, size_t s) { (void)z; return realloc(p, s); }
static void  zd(struct _malloc_zone_t *z) { (void)z; }

static struct _malloc_zone_t macify_zone = {
    .size = zs, .malloc = zm, .calloc = zc, .valloc = zv,
    .free = zf, .realloc = zr, .destroy = zd,
};

void *malloc_create_zone(size_t start, unsigned flags) { (void)start; (void)flags; return &macify_zone; }
void *malloc_default_zone(void) { return &macify_zone; }

/* task_info - Mach task info. Stub. */
int task_info(uint32_t target_task, int flavor, void *task_info_out, uint32_t *count) {
    (void)target_task; (void)flavor;
    if (task_info_out && count) {
        memset(task_info_out, 0, *count);
    }
    return 0;
}

/* task_policy_set - Mach task policy. Stub, returns 0 (KERN_SUCCESS).
 * nvim uses this to set thread QoS (quality of service) which has no
 * Linux equivalent. Returning success lets nvim continue. */
int task_policy_set(uint32_t task, int policy, int task_info_out, uint32_t count) {
    (void)task; (void)policy; (void)task_info_out; (void)count;
    return 0;  /* KERN_SUCCESS */
}

/* sscanf_l - locale-aware sscanf. We don't have locale-aware scanning,
 * so just delegate to regular sscanf with the C locale. */
#include <stdio.h>
#include <stdarg.h>
int sscanf_l(const char *str, void *loc, const char *fmt, ...) {
    (void)loc;
    va_list ap;
    va_start(ap, fmt);
    /* We can't call vsscanf directly because it doesn't exist as a
     * public symbol. Use sscanf with a trick: parse the format string
     * to count arguments. For now, just call vsscanf if available. */
    int r = vsscanf(str, fmt, ap);
    va_end(ap);
    return r;
}

/* proc_regionfilename - get the pathname for a memory region. Stub. */
int proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize) {
    (void)pid; (void)address;
    if (buffer && buffersize > 0) {
        ((char *)buffer)[0] = '\0';
    }
    return 0;
}

/* notify_is_valid_token - check if a notification token is valid. */
int notify_is_valid_token(int token) {
    (void)token;
    return 0;  /* invalid */
}

/* res_9_* - DNS resolver functions (BIND resolver library) */
int res_9_ninit(void *state) { (void)state; return -1; }
int res_9_nclose(void *state) { (void)state; return 0; }
int res_9_nsearch(void *state, const char *dname, int *domain, void *answer, int anslen) {
    (void)state; (void)dname; (void)domain; (void)answer; (void)anslen;
    return -1;
}

/* XPC stubs */
void *xpc_date_create_from_current(void) { return NULL; }

/* CF stubs needed by Go */
void *CFDateCreate(void *alloc, double time) { (void)alloc; (void)time; return NULL; }
/* CFStringCreateWithBytes is now defined in misc/objc_compat.c with a
 * proper sc_obj wrapper so CFStringGetBytes etc. work. */
void *CFStringCreateExternalRepresentation(void *alloc, const void *str,
                                           int encoding, int lossByte) {
    (void)alloc; (void)str; (void)encoding; (void)lossByte;
    return NULL;
}

/* Security framework stubs needed by Go */
void *SecCertificateCopyData(void *cert) { (void)cert; return NULL; }
void *SecTrustCopyCertificateChain(void *trust) { (void)trust; return NULL; }
int SecTrustSetVerifyDate(void *trust, void *date) { (void)trust; (void)date; return 0; }


/* GnuTLS stubs - wget links against macOS GnuTLS which has incompatible
 * struct layouts with Linux GnuTLS. Provide stubs that return success
 * for init and no-op for everything else.
 * This allows wget --version and --help to work.
 * Actual HTTPS downloads will fail, but that's expected. */

int gnutls_global_init(void) { return 0; }
void gnutls_global_deinit(void) { }
int gnutls_init(void **session, int flags) { (void)flags; if (session) *session = NULL; return 0; }
void gnutls_deinit(void *session) { (void)session; }
int gnutls_set_default_priority(void *session) { (void)session; return 0; }
int gnutls_priority_set_direct(void *session, const char *prio, const char **err) { (void)session; (void)prio; if (err) *err = NULL; return 0; }
int gnutls_credentials_set(void *session, int type, void *cred) { (void)session; (void)type; (void)cred; return 0; }
int gnutls_handshake(void *session) { (void)session; return 0; }
int gnutls_bye(void *session, int how) { (void)session; (void)how; return 0; }
int gnutls_record_recv(void *session, void *data, size_t size) { (void)session; (void)data; (void)size; return -1; }
int gnutls_record_send(void *session, const void *data, size_t size) { (void)session; (void)data; return (int)size; }
int gnutls_error_is_fatal(int error) { (void)error; return 1; }
int gnutls_alert_get(void *session) { (void)session; return 0; }
const char *gnutls_alert_get_name(int alert) { (void)alert; return "unknown"; }
int gnutls_certificate_allocate_credentials(void **cred) { if (cred) *cred = NULL; return 0; }
void gnutls_certificate_free_credentials(void *cred) { (void)cred; }
int gnutls_certificate_set_x509_system_trust(void *cred) { (void)cred; return 0; }
int gnutls_certificate_set_x509_trust_file(void *cred, const char *f, int type) { (void)cred; (void)f; (void)type; return 0; }
int gnutls_certificate_set_x509_crl_file(void *cred, const char *f, int type) { (void)cred; (void)f; (void)type; return 0; }
int gnutls_certificate_set_x509_key_file(void *cred, const char *c, const char *k, int type) { (void)cred; (void)c; (void)k; (void)type; return 0; }
int gnutls_certificate_set_verify_flags(void *cred, int flags) { (void)cred; (void)flags; return 0; }
const void *gnutls_certificate_get_peers(void *session, unsigned int *count) { (void)session; if (count) *count = 0; return NULL; }
int gnutls_certificate_verify_peers2(void *session, unsigned int *status) { (void)session; if (status) *status = 0; return 0; }
int gnutls_certificate_type_get(void *session) { (void)session; return 1; }
void gnutls_free(void *ptr) { (void)ptr; }
