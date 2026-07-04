/* misc.c — remaining macOS compatibility stubs */
#include "../shim.h"
#include <sys/mount.h>
#include <ucontext.h>
#include <stdarg.h>
#include <malloc.h>

/* ── libgcc_s loading for _Unwind_* functions ────────────────── */

static void *libgcc_s_handle = NULL;

static void ensure_libgcc(void) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (!libgcc_s_handle)
            libgcc_s_handle = dlopen("libgcc_s.so.2", RTLD_NOW | RTLD_GLOBAL);
    }
}

/* dyld_stub_binder — macOS lazy binding handler. Mac-ify resolves all lazy
 * binds eagerly at load time, so this should never be called. If it is, a
 * lazy symbol wasn't resolved — log and abort. */

void dyld_stub_binder(void) {
    fprintf(stderr, "macify: dyld_stub_binder called — a lazy symbol was not resolved at load time\n");
    abort();
}

/* ___chkstk_darwin — stack probe function.
 * 
 * macOS calls this before large stack allocations to touch each page
 * and trigger guard page exceptions. On Linux, stack growth is handled
 * automatically by the kernel, so this is a no-op.
 * 
 * The argument is the stack size in bytes. The function must not be
 * optimized away — it's called with a specific stack layout.
 */

__attribute__((noinline, optnone))
void ___chkstk_darwin(unsigned long size) {
    (void)size;
    /* No-op on Linux — the kernel handles stack growth automatically. */
    __asm__ volatile("" ::: "memory");
}

/* Also provide __chkstk_darwin (two underscores) for completeness */
__attribute__((noinline, optnone))
void __chkstk_darwin(unsigned long size) {
    (void)size;
    __asm__ volatile("" ::: "memory");
}

void dispatch_async(void *queue, void *block) {
    (void)queue; (void)block;
    /* No-op for now */
}

void dispatch_sync(void *queue, void *block) {
    (void)queue;
    /* Execute block synchronously — but we don't know the block layout.
     * For now, no-op. */
}

void *dispatch_get_main_queue(void) {
    static char main_queue_placeholder;
    return &main_queue_placeholder;
}

void dispatch_release(void *object) {
    (void)object;
}

void *dispatch_retain(void *object) {
    return object;
}

/* dispatch_semaphore stubs — Rust uses these for synchronization.
 * We provide minimal working implementations using POSIX semaphores. */
#include <semaphore.h>

void *dispatch_semaphore_create(long value) {
    sem_t *sem = malloc(sizeof(sem_t));
    if (sem) sem_init(sem, 0, (unsigned)value);
    return sem;
}

long dispatch_semaphore_signal(void *sem) {
    if (sem) sem_post((sem_t *)sem);
    return 0;
}

long dispatch_semaphore_wait(void *sem, void *timeout) {
    (void)timeout;  /* ignore timeout for now */
    if (sem) {
        while (sem_wait((sem_t *)sem) == -1 && errno == EINTR) continue;
    }
    return 0;
}

unsigned long dispatch_time(unsigned long when, long delta) {
    (void)when; (void)delta;
    return 0;  /* 0 = DISPATCH_TIME_NOW */
}


/* srandomdev — seed random from /dev/random */
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

/* kCFTypeArrayCallBacks — a static struct that CoreFoundation uses for
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

/* Security framework TLS stubs — curl uses these for certificate validation.
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
    return 0;  /* success — trust everything */
}
int SecTrustSetOCSPResponse(void *trust, void *response) {
    (void)trust; (void)response;
    return 0;
}

/* notify_* — macOS notification system. Stub to no-op. */
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

/* ___mb_cur_max_l — macOS locale-specific multibyte character max length.
 * Return 1 (single-byte locale). */
int ___mb_cur_max_l(void *loc) {
    (void)loc;
    return 1;
}

/* ___mb_cur_max — macOS global multibyte character max length.
 * Used by wget's stdio macros. Return 1 (single-byte locale). */
int ___mb_cur_max(void) {
    return 1;
}

/* __mb_cur_max — alternate symbol name (some binaries use this). */
int __mb_cur_max(void) {
    return 1;
}

/* getprogname — macOS function to get the program name.
 * Returns __progname which we provide in shim_core.c. */
const char *getprogname(void) {
    extern char *__progname;
    return __progname ? __progname : "macify-app";
}

/* fpurge — macOS/BSD function to discard pending data in a stream's buffer.
 * glibc has __fpurge (note the leading underscore). We map fpurge to it. */
#include <stdio_ext.h>
int fpurge(FILE *stream) {
    if (stream) __fpurge(stream);
    return 0;
}

/* libiconv — macOS uses GNU libiconv as a separate library with `libiconv`
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

/* libintl — macOS uses GNU gettext as a separate library with `libintl`
 * prefixed function names. glibc has gettext built-in (without prefix).
 * We provide stubs that delegate to glibc or return no-op results. */
char *libintl_gettext(const char *msgid) {
    return (char *)msgid;  /* no translation — return original */
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
/* libintl_setlocale — glibc has setlocale, delegate to it. */
#include <locale.h>
char *libintl_setlocale(int category, const char *locale) {
    return setlocale(category, locale);
}

/* nl_langinfo — macOS function to query locale information.
 * tree uses nl_langinfo(CODESET) to check if the terminal supports UTF-8.
 * If it returns "ANSI_X3.4-1968" (ASCII), tree escapes non-ASCII filenames
 * as octal. We delegate to glibc's nl_langinfo.
 * macOS nl_item constants: CODESET=14, same as Linux. */
#include <langinfo.h>
char *nl_langinfo(int item) {
    static char *(*real_nl_langinfo)(int) = NULL;
    if (!real_nl_langinfo) real_nl_langinfo = dlsym(RTLD_NEXT, "nl_langinfo");
    if (!real_nl_langinfo) return "ANSI_X3.4-1968";  /* ASCII fallback */
    return real_nl_langinfo(item);
}

/* px_proxy_factory_* — libproxy. Not available on this system. Stub them
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

/* sigsetjmp — macOS uses sigsetjmp directly. glibc has __sigsetjmp (internal)
 * and sigsetjmp as a macro that calls __sigsetjmp. We need to undef the
 * macro to actually create a sigsetjmp symbol. */
#include <setjmp.h>
#undef sigsetjmp
extern int __sigsetjmp(sigjmp_buf env, int savesigs);
int sigsetjmp(sigjmp_buf env, int savesigs) __asm__("sigsetjmp");
int sigsetjmp(sigjmp_buf env, int savesigs) {
    return __sigsetjmp(env, savesigs);
}

/* ___darwin_check_fd_set_overflow — macOS fd_set overflow checker.
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
 * garbage — usually 0) causes FD_SET to silently skip setting the bit,
 * leaving the fd_set empty. select() then has nothing to wait on and
 * blocks until its timeout — exactly the "HTTPS hangs forever" symptom
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

/* __longjmp / __setjmp — macOS uses these instead of longjmp/setjmp.
 * Map to glibc's longjmp/setjmp. */
#include <setjmp.h>
void __longjmp(jmp_buf env, int val) { longjmp(env, val); }
int __setjmp(jmp_buf env) { return setjmp(env); }

/* ___strncpy_chk — fortified strncpy */
char *___strncpy_chk(char *dst, const char *src, size_t n, size_t dstlen) {
    (void)dstlen;
    return strncpy(dst, src, n);
}

/* ___cxa_atexit — C++ atexit handler. Map to atexit. */
int ___cxa_atexit(void (*fn)(void *), void *arg, void *dso) {
    (void)dso;
    /* We can't perfectly map cxa_atexit (which takes an arg) to atexit.
     * For simplicity, just call atexit with a wrapper if arg is NULL. */
    if (arg == NULL) {
        atexit((void (*)(void))fn);
    }
    return 0;
}

/* memset_s — C11 memset with guaranteed no elision. Just call memset. */
int memset_s(void *s, size_t smax, int c, size_t n) {
    if (s && n > 0) memset(s, c, n < smax ? n : smax);
    return 0;
}

/* arc4random_buf — fill buffer with random bytes (already defined above) */

/* connectx — macOS extended connect(). We implement it by translating
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

/* CFTimeZoneResetSystem — no-op (we don't track timezone changes) */
void CFTimeZoneResetSystem(void) {
    /* no-op */
}



/* kqueue / kevent — macOS kernel event system. No Linux equivalent.
 * Return -1 (ENOSYS) so callers can fall back to polling.
 * c-ares on macOS tries kqueue first; when this returns -1, c-ares falls
 * back to poll or select. */
int kqueue(void) {
    errno = ENOSYS;
    return -1;
}
int kevent(int kq, const void *changelist, int nchanges,
           void *eventlist, int nevents,
           const void *timeout) {
    (void)kq; (void)changelist; (void)nchanges;
    (void)eventlist; (void)nevents; (void)timeout;
    errno = ENOSYS;
    return -1;
}

/* getcontext / setcontext / makecontext — macOS ucontext_t has a completely
 * different layout from Linux's ucontext_t. We cannot delegate to glibc's
 * versions because the struct layouts are incompatible.
 *
 * OpenSSL's async API uses these. We return 0 (success) from getcontext
 * and makecontext so OpenSSL's async init doesn't fail. The async API
 * won't actually work (contexts are invalid), but SSL_CTX_new succeeds
 * because async is optional. */
#include <ucontext.h>
int getcontext(ucontext_t *ucp) {
    /* Return 0 (success) — OpenSSL's async init needs this to not fail.
     * The context won't actually be usable, but async is optional. */
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: getcontext(%p) -> 0\n", ucp);
        (void)write(2, b, n);
    }
    if (ucp) memset(ucp, 0, sizeof(*ucp));
    return 0;
}

int setcontext(const ucontext_t *ucp) {
    (void)ucp;
    errno = ENOSYS;
    return -1;
}

void makecontext(ucontext_t *ucp, void (*func)(void), int argc, ...) {
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: makecontext(%p, %p, %d)\n", ucp, (void*)func, argc);
        (void)write(2, b, n);
    }
    (void)ucp; (void)func; (void)argc;
    /* no-op — async won't work but SSL_CTX_new should succeed */
}

/* swapcontext — OpenSSL's async API also uses this. Return 0 (success). */
int swapcontext(ucontext_t *oucp, const ucontext_t *ucp) {
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: swapcontext(%p, %p) -> 0\n", oucp, ucp);
        (void)write(2, b, n);
    }
    (void)oucp; (void)ucp;
    return 0;
}

/* ── OpenSSL OSSL_LIB_CTX stubs ─────────────────────────────────
 * curl 8.x uses SSL_CTX_new_ex(libctx, ...) which requires an OSSL_LIB_CTX.
 * On macOS, curl is built with its own copy of OpenSSL, so OSSL_LIB_CTX
 * is an opaque struct allocated by OSSL_LIB_CTX_new(). We provide a
 * minimal stub: OSSL_LIB_CTX_new returns a non-NULL sentinel, and
 * OSSL_LIB_CTX_free is a no-op. SSL_CTX_new_ex then uses this libctx
 * to create the SSL context.
 *
 * The actual OpenSSL library on the system (libssl.so) has its own
 * internal OSSL_LIB_CTX, but since curl was compiled expecting the
 * macOS OpenSSL symbols, we provide these stubs. The system's libssl
 * will use its own internal default context when SSL_CTX_new_ex is
 * called with our stub libctx (it ignores the libctx parameter if
 * OPENSSL_init_crypto hasn't been called with it). */

static char macify_ossl_lib_ctx_sentinel[64] __attribute__((aligned(16))) = {0};

void *OSSL_LIB_CTX_new(void) {
    return macify_ossl_lib_ctx_sentinel;
}
void OSSL_LIB_CTX_free(void *ctx) {
    (void)ctx;
}
void *OSSL_LIB_CTX_get0_global_default(void) {
    return macify_ossl_lib_ctx_sentinel;
}
void *OSSL_LIB_CTX_get_data(void *ctx, int idx) {
    (void)ctx; (void)idx;
    return NULL;
}
int OSSL_LIB_CTX_load_config(void *ctx, const char *config) {
    (void)ctx; (void)config;
    return 1;  /* success */
}
int OSSL_LIB_CTX_get_conf_diagnostics(void *ctx) {
    (void)ctx;
    return 0;
}

/* OPENSSL_init_crypto — curl's internal OpenSSL calls this to initialize
 * crypto subsystems. We wrap it to debug failures: if it returns 0
 * (failure), we print the ossl_init_*_ret_ globals to see which init
 * step failed.
 *
 * However, curl's OPENSSL_init_crypto is STATICALLY LINKED into the curl
 * binary, so our shim's OPENSSL_init_crypto is NOT called by curl's
 * internal code. It may be called by other code though. We just pass
 * through to... well, there's nothing to pass through to. We return 1
 * (success) since we can't actually initialize curl's internal OpenSSL. */
int OPENSSL_init_crypto(uint64_t settings, void *opts) {
    (void)settings; (void)opts;
    if (getenv("MACIFY_SSL_DEBUG")) {
        const char msg[] = "SSL_DEBUG: OPENSSL_init_crypto called (returning 1)\n";
        (void)write(2, msg, sizeof(msg)-1);
    }
    return 1;
}

int OPENSSL_init_ssl(uint64_t settings, void *opts) {
    (void)settings; (void)opts;
    if (getenv("MACIFY_SSL_DEBUG")) {
        const char msg[] = "SSL_DEBUG: OPENSSL_init_ssl called (returning 1)\n";
        (void)write(2, msg, sizeof(msg)-1);
    }
    return 1;
}

/* proc_* functions are implemented in shim_mach.c with real /proc reading */

/* __slbsearch — macOS's bsearch variant (secure). Map to bsearch. */

void *__slbsearch(const void *key, const void *base, size_t nel, size_t width,
                  int (*compar)(const void *, const void *)) {
    return bsearch(key, base, nel, width, compar);
}

/* arc4random / arc4random_uniform — macOS random functions. */

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

/* _NSLog / _CFLog — logging stubs. */

void NSLog(void *format, ...) {
    (void)format;
    fprintf(stderr, "[NSLog called]\n");
}

void CFLog(int level, void *format, ...) {
    (void)level; (void)format;
    fprintf(stderr, "[CFLog called]\n");
}

/* macOS math function aliases.
 * macOS has __exp10, __expm1, etc. (2 underscores) which map to
 * standard exp10, expm1, etc. in libm.
 */
#include <math.h>
double __exp10(double x) { return exp10(x); }
double __expm1(double x) { return expm1(x); }
double __log1p(double x) { return log1p(x); }
double __hypot(double x, double y) { return hypot(x, y); }
double __log2(double x) { return log2(x); }
double __logb(double x) { return logb(x); }
double __cbrt(double x) { return cbrt(x); }
double __atan2(double y, double x) { return atan2(y, x); }
double __pow(double x, double y) { return pow(x, y); }

/* __maskrune — macOS character classification.
 * 
 * Returns the runetype flags for character `ch` ANDed with `mask`.
 * Used by isalpha(), isdigit(), etc. on macOS.
/* Functions that glibc inlines but macOS exports as dynamic symbols.
 * glibc only exports __cxa_atexit, not atexit. macOS binaries
 * reference atexit directly via the GOT.
 */
extern int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);

static void atexit_wrapper(void *arg) {
    void (*func)(void) = (void (*)(void))arg;
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
    /* When MACIFY_SSL_DEBUG is set, print OpenSSL's ossl_init_*_ret_
     * globals so we can see which RUN_ONCE init function returned 0
     * (causing OPENSSL_init_crypto to fail). Must run before fflush
     * so the output isn't reordered. */
    if (getenv("MACIFY_SSL_DEBUG")) {
        macify_print_ret_globals();
    }
    /* Run glibc's atexit chain via __cxa_finalize(NULL) (which runs
     * all handlers registered with __cxa_atexit, including ours).
     * This is what glibc's exit() does internally. */
    extern void __cxa_finalize(void *);
    __cxa_finalize(NULL);
    fflush(NULL);  /* Flush all stdio streams */
    _exit(status);
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



/* ── macOS malloc zone API (sqlite3 uses these) ── */

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
    .zone_name = "macify",
};

void *malloc_create_zone(size_t start, unsigned flags) { (void)start; (void)flags; return &macify_zone; }
void *malloc_default_zone(void) { return &macify_zone; }
void malloc_set_zone_name(void *zone, const char *name) { (void)zone; (void)name; }
size_t malloc_size(const void *ptr) {
    if (!ptr) return 0;
    size_t r = malloc_usable_size((void *)ptr);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "macify: malloc_size(%p) -> %zu\n", ptr, r);
        (void)write(2, b, n);
    }
    return r;
}
void *malloc_zone_malloc(void *zone, size_t size) {
    void *r = malloc(size);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[160];
        int n = snprintf(b, sizeof(b), "macify: malloc_zone_malloc(zone=%p, %zu) -> %p\n", zone, size, r);
        (void)write(2, b, n);
    }
    return r;
}
void *malloc_zone_realloc(void *zone, void *ptr, size_t size) {
    void *r = realloc(ptr, size);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[160];
        int n = snprintf(b, sizeof(b), "macify: malloc_zone_realloc(zone=%p, %p, %zu) -> %p\n", zone, ptr, size, r);
        (void)write(2, b, n);
    }
    return r;
}
void malloc_zone_free(void *zone, void *ptr) {
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "macify: malloc_zone_free(zone=%p, %p)\n", zone, ptr);
        (void)write(2, b, n);
    }
    free(ptr);
}
void *malloc_zone_calloc(void *zone, size_t n, size_t size) {
    void *r = calloc(n, size);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[160];
        int m = snprintf(b, sizeof(b), "macify: malloc_zone_calloc(zone=%p, %zu, %zu) -> %p\n", zone, n, size, r);
        (void)write(2, b, m);
    }
    return r;
}
void *malloc_zone_memalign(void *zone, size_t align, size_t size) {
    void *r = NULL;
    (void)zone;
    posix_memalign(&r, align, size);
    return r;
}

