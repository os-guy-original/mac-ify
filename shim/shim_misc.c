#include "shim.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* ── SCDynamicStore stubs ──────────────────────────────────────────────
 *
 * macOS curl's c-ares dlopens SystemConfiguration.framework and calls
 * SCDynamicStoreCreate + SCDynamicStoreCopyValue to read the system DNS
 * configuration (instead of /etc/resolv.conf). Since SystemConfiguration
 * doesn't exist on Linux, our dlopen override (in shim_io.c) returns a
 * fake handle, and our dlsym override returns these stub functions.
 *
 * The stubs parse /etc/resolv.conf and return DNS server addresses as
 * fake CFArray/CFString/CFDictionary objects (which are just heap-allocated
 * structs tagged with a type marker).
 *
 * c-ares's macOS code path is roughly:
 *   store = SCDynamicStoreCreate(NULL, CFSTR("c-ares"), NULL, NULL);
 *   dict  = SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/DNS"));
 *   arr   = CFDictionaryGetValue(dict, CFSTR("ServerAddresses"));
 *   count = CFArrayGetCount(arr);
 *   for (i=0; i<count; i++) {
 *       str = CFArrayGetValueAtIndex(arr, i);
 *       CFStringGetCString(str, buf, sizeof(buf), kCFStringEncodingUTF8);
 *       // use buf as DNS server IP
 *   }
 *   CFRelease(dict); CFRelease(store);
 */

/* Tag values for our fake CF objects. */
#define SC_TAG_STRING     0x5C01  /* fake CFString */
#define SC_TAG_ARRAY      0x5C02  /* fake CFArray */
#define SC_TAG_DICT       0x5C03  /* fake CFDictionary */
#define SC_TAG_STORE      0x5C04  /* fake SCDynamicStoreRef */

struct sc_obj {
    uint32_t tag;       /* one of SC_TAG_* */
    uint32_t count;     /* element count for arrays/dicts */
    void *data;         /* payload (string, or array of pointers) */
};

/* Parse /etc/resolv.conf and return up to 8 nameserver IPs as a NULL-terminated
 * array of strings. Caller must not free (returns static buffer). */
static const char *const *read_resolv_conf_nameservers(void) {
    static char *servers[16];
    static char buf[16][64];
    static int initialized = 0;
    if (initialized) return (const char *const *)servers;

    int n = 0;
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) && n < 15) {
            /* Skip comments and blank lines */
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == '\n' || *p == '\0') continue;
            /* Look for "nameserver X.X.X.X" */
            if (strncmp(p, "nameserver", 10) == 0) {
                p += 10;
                while (*p == ' ' || *p == '\t') p++;
                /* Trim trailing whitespace */
                char *end = p;
                while (*end && *end != '\n' && *end != ' ' && *end != '\t') end++;
                *end = '\0';
                if (*p) {
                    strncpy(buf[n], p, sizeof(buf[n]) - 1);
                    buf[n][sizeof(buf[n]) - 1] = '\0';
                    servers[n] = buf[n];
                    n++;
                }
            }
        }
        fclose(fp);
    }
    servers[n] = NULL;
    initialized = 1;
    return (const char *const *)servers;
}

/* SCDynamicStoreCreate — return a fake store ref. */
void *macify_SCDynamicStoreCreate(void *alloc, const void *name, void *cb, void *ctx) {
    (void)alloc; (void)name; (void)cb; (void)ctx;
    struct sc_obj *o = (struct sc_obj *)calloc(1, sizeof(*o));
    o->tag = SC_TAG_STORE;
    return o;
}

/* SCDynamicStoreCopyValue — return a fake CFDictionary containing a
 * "ServerAddresses" key with a CFArray of DNS server CFStrings.
 * The `key` parameter is ignored (we always return DNS config). */
void *macify_SCDynamicStoreCopyValue(void *store, const void *key) {
    (void)store; (void)key;
    const char *const *servers = read_resolv_conf_nameservers();
    if (!servers[0]) return NULL;

    /* Build the array of CFString refs (each is a sc_obj with tag=STRING). */
    int count = 0;
    while (servers[count]) count++;
    void **arr_data = (void **)calloc(count + 1, sizeof(void *));
    for (int i = 0; i < count; i++) {
        struct sc_obj *s = (struct sc_obj *)calloc(1, sizeof(*s));
        s->tag = SC_TAG_STRING;
        s->count = (uint32_t)strlen(servers[i]);
        s->data = strdup(servers[i]);
        arr_data[i] = s;
    }

    /* Build the CFArray. */
    struct sc_obj *arr = (struct sc_obj *)calloc(1, sizeof(*arr));
    arr->tag = SC_TAG_ARRAY;
    arr->count = count;
    arr->data = arr_data;

    /* Build the CFDictionary. c-ares only looks up "ServerAddresses",
     * so we use the dictionary's data field as the array directly. */
    struct sc_obj *dict = (struct sc_obj *)calloc(1, sizeof(*dict));
    dict->tag = SC_TAG_DICT;
    dict->count = 1;
    dict->data = arr;  /* store the array as the dict's payload */

    return dict;
}

/* CFRelease — free the fake CF object. */
void macify_CFRelease(void *cf) {
    if (!cf) return;
    struct sc_obj *o = (struct sc_obj *)cf;
    if (o->tag == SC_TAG_STRING) {
        free(o->data);
    } else if (o->tag == SC_TAG_ARRAY) {
        void **arr = (void **)o->data;
        for (uint32_t i = 0; i < o->count; i++) {
            macify_CFRelease(arr[i]);
        }
        free(arr);
    } else if (o->tag == SC_TAG_DICT) {
        macify_CFRelease(o->data);
    }
    /* SC_TAG_STORE has no payload */
    free(o);
}

/* CFStringCreateWithCString — create a fake CFString from a C string. */
void *macify_CFStringCreateWithCString(void *alloc, const char *cstr, unsigned int encoding) {
    (void)alloc; (void)encoding;
    if (!cstr) return NULL;
    struct sc_obj *s = (struct sc_obj *)calloc(1, sizeof(*s));
    s->tag = SC_TAG_STRING;
    s->count = (uint32_t)strlen(cstr);
    s->data = strdup(cstr);
    return s;
}

/* CFStringGetCString — extract the C string from a fake CFString. */
int macify_CFStringGetCString(const void *cfstr, char *buf, long buf_size, unsigned int encoding) {
    (void)encoding;
    if (!cfstr || !buf || buf_size <= 0) return 0;
    const struct sc_obj *s = (const struct sc_obj *)cfstr;
    if (s->tag != SC_TAG_STRING) return 0;
    strncpy(buf, (const char *)s->data, buf_size - 1);
    buf[buf_size - 1] = '\0';
    return 1;
}

long macify_CFStringGetLength(const void *cfstr) {
    if (!cfstr) return 0;
    const struct sc_obj *s = (const struct sc_obj *)cfstr;
    if (s->tag != SC_TAG_STRING) return 0;
    return (long)s->count;
}

long macify_CFStringGetMaximumSizeForEncoding(long length, unsigned int encoding) {
    (void)encoding;
    return length * 4 + 1;  /* worst case UTF-8 expansion */
}

/* CFArrayGetCount — return element count of fake CFArray. */
long macify_CFArrayGetCount(const void *arr) __asm__("CFArrayGetCount");
long macify_CFArrayGetCount(const void *arr) {
    if (!arr) return 0;
    const struct sc_obj *a = (const struct sc_obj *)arr;
    if (a->tag != SC_TAG_ARRAY) return 0;
    return (long)a->count;
}

/* CFArrayGetValueAtIndex — return element at index from fake CFArray. */
const void *macify_CFArrayGetValueAtIndex(const void *arr, long idx) __asm__("CFArrayGetValueAtIndex");
const void *macify_CFArrayGetValueAtIndex(const void *arr, long idx) {
    if (!arr) return NULL;
    const struct sc_obj *a = (const struct sc_obj *)arr;
    if (a->tag != SC_TAG_ARRAY || idx < 0 || (uint32_t)idx >= a->count) return NULL;
    void **data = (void **)a->data;
    return data[idx];
}

/* CFDictionaryGetValue — c-ares only looks up "ServerAddresses" from the dict.
 * We stored the array directly in dict->data, so return it. */
const void *macify_CFDictionaryGetValue(const void *dict, const void *key) __asm__("CFDictionaryGetValue");
const void *macify_CFDictionaryGetValue(const void *dict, const void *key) {
    (void)key;  /* ignore key, we only have one entry */
    if (!dict) return NULL;
    const struct sc_obj *d = (const struct sc_obj *)dict;
    if (d->tag != SC_TAG_DICT) return NULL;
    return d->data;
}

/* dns_configuration_copy — macOS modern DNS config API. c-ares calls this
 * to get the system DNS configuration. We return a config struct containing
 * the DNS servers from /etc/resolv.conf, formatted as macOS-style sockaddr_in
 * (with sin_len at offset 0).
 *
 * Note: The exact struct layout varies by macOS version. We use a layout
 * where `domain` is a char* (8 bytes) rather than uint32_t index, which
 * matches newer macOS versions. */
struct macos_dns_resolver {
    char *domain;                 /* 0: domain string (or NULL) */
    uint32_t n_nameserver;        /* 8: number of nameservers */
    uint32_t padding1;            /* 12: padding for alignment */
    struct sockaddr **nameserver; /* 16: array of nameserver sockaddr */
    uint32_t n_search;            /* 24: number of search domains */
    uint32_t padding2;            /* 28: padding */
    char **search;                /* 32: array of search domain strings */
    uint32_t n_sortaddr;          /* 40: number of sort addresses */
    uint32_t padding3;            /* 44: padding */
    void *sortaddr;               /* 48: array of sort addresses */
    char *options;                /* 56: options string (or NULL) */
    uint32_t timeout;             /* 64: timeout in seconds */
    uint32_t reach_flags;         /* 68: reachability flags */
    uint32_t reserved[6];         /* 72: reserved */
};

struct macos_dns_config {
    uint32_t n_resolver;                 /* 0: number of resolvers */
    uint32_t reserved;                   /* 4: reserved */
    struct macos_dns_resolver **resolver;/* 8: array of resolver pointers */
    uint64_t timeout;                    /* 16: timeout in seconds */
    int32_t search_order;                /* 24: search order */
    uint32_t n_search;                   /* 28: number of search domains */
    char **search;                       /* 32: array of search domain strings */
    uint32_t n_sortaddr;                 /* 40: number of sort addresses */
    uint32_t padding;                    /* 44: padding */
    void *sortaddr;                      /* 48: array of sort addresses */
    char *options;                       /* 56: options string */
    uint32_t flags;                      /* 64: flags */
    uint32_t reach_flags;                /* 68: reachability flags */
    uint32_t reserved2[5];               /* 72: reserved */
};

/* macOS sockaddr_in layout:
 *   uint8_t sin_len;     // 0 (16)
 *   uint8_t sin_family;  // 1 (2 = AF_INET)
 *   uint16_t sin_port;   // 2 (network byte order)
 *   uint32_t sin_addr;   // 4 (network byte order)
 *   uint8_t sin_zero[8]; // 8
 * total 16 bytes */
struct macos_sockaddr_in {
    uint8_t  sin_len;
    uint8_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

/* dns_configuration_copy — macOS modern DNS config API. c-ares calls this
 * to get the system DNS configuration. We return NULL because the exact
 * struct layout of dns_config_t varies by macOS version and getting it
 * wrong crashes c-ares.
 *
 * Instead, we handle DNS in connect(): when c-ares connects to 127.0.0.1:53
 * (its hardcoded fallback when no DNS config is available), our connect()
 * override redirects to the real DNS server from /etc/resolv.conf. */
void *macify_dns_configuration_copy(void) {
    return NULL;
}

void macify_dns_configuration_free(void *config) {
    if (!config) return;
    struct macos_dns_config *cfg = (struct macos_dns_config *)config;
    for (uint32_t i = 0; i < cfg->n_resolver; i++) {
        struct macos_dns_resolver *res = cfg->resolver[i];
        if (!res) continue;
        for (uint32_t j = 0; j < res->n_nameserver; j++) {
            free(res->nameserver[j]);
        }
        free(res->nameserver);
        free(res);
    }
    free(cfg->resolver);
    free(cfg);
}

void *__memset_chk(void *dst, int c, size_t len, size_t dstlen) {
    if (len > dstlen) abort();
    return memset(dst, c, len);
}

void *__memcpy_chk(void *dst, const void *src, size_t len, size_t dstlen) {
    if (len > dstlen) abort();
    return memcpy(dst, src, len);
}

void *__memmove_chk(void *dst, const void *src, size_t len, size_t dstlen) {
    if (len > dstlen) abort();
    return memmove(dst, src, len);
}

void *__strcpy_chk(void *dst, const char *src, size_t dstlen) {
    size_t len = strlen(src) + 1;
    if (len > dstlen) abort();
    return memcpy(dst, src, len);
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
/* _DefaultRuneLocale — macOS rune/cType table.
 * 
 * macOS uses a rune table for character classification (isalpha, etc).
 * The _DefaultRuneLocale global is a struct _RuneLocale that contains
 * the default C locale character table. On Linux, character classification
 * uses a different mechanism (locale.h).
 * 
 * We provide a zeroed-out table. This means isalpha() etc. won't work
 * correctly, but the binary can at least load and run. For proper
 * classification support, we'd need to populate the table fields.
 */

#include <ctype.h>

/* macOS _RuneLocale structure (simplified - enough to not crash) */
struct _macify_RuneLocale {
    char magic[8];         /* "RuneMag1" */
    uint32_t encoding;
    void *sgetrune;
    void *sputrune;
    uint32_t invalid_rune;
    uint32_t *runetype;    /* 256 entries */
    int16_t *maplower;     /* 256 entries */
    int16_t *mapupper;     /* 256 entries */
    void *runes;
    uint32_t nrunes;
    uint32_t *runetype_ext;
    int16_t *maplower_ext;
    int16_t *mapupper_ext;
    uint32_t variablehigh;
};

/* Provide a static _DefaultRuneLocale that's big enough to not crash.
 * The macOS binary reads from _DefaultRuneLocale to do character classification.
 * We'll populate the runetype table with basic ASCII classification. */
uint32_t macify_runetype[256];
int16_t macify_maplower[256];
int16_t macify_mapupper[256];

/* _DefaultRuneLocale has 2 underscores in binary → strip 1 → _DefaultRuneLocale (1 underscore) */
struct _macify_RuneLocale _DefaultRuneLocale = {
    .magic = "RuneMag1",
    .encoding = 0,
    .sgetrune = NULL,
    .sputrune = NULL,
    .invalid_rune = 0xFFFD,
    .runetype = macify_runetype,
    .maplower = macify_maplower,
    .mapupper = macify_mapupper,
    .runes = NULL,
    .nrunes = 256,
    .runetype_ext = NULL,
    .maplower_ext = NULL,
    .mapupper_ext = NULL,
    .variablehigh = 0,
};

__attribute__((constructor))
static void macify_init_rune(void) {
    /* Populate basic ASCII character tables */
    for (int c = 0; c < 256; c++) {
        /* Basic runetype flags: bit 0=upper, 1=lower, 2=digit, 3=space,
         * 4=punct, 5=cntrl, 6=blank, 7=hex, 8=print, 9=graph, 10=alpha, 11=alnum */
        uint32_t flags = 0;
        if (isupper(c))  flags |= (1u << 0);
        if (islower(c))  flags |= (1u << 1);
        if (isdigit(c))  flags |= (1u << 2);
        if (isspace(c))  flags |= (1u << 3);
        if (ispunct(c))  flags |= (1u << 4);
        if (iscntrl(c))  flags |= (1u << 5);
        if (isblank(c))  flags |= (1u << 6);
        if (isxdigit(c)) flags |= (1u << 7);
        if (isprint(c))  flags |= (1u << 8);
        if (isgraph(c))  flags |= (1u << 9);
        if (isalpha(c))  flags |= (1u << 10);
        if (isalnum(c))  flags |= (1u << 11);
        macify_runetype[c] = flags;
        macify_maplower[c] = tolower(c);
        macify_mapupper[c] = toupper(c);
    }
}
/* _memset_pattern16 — macOS-specific memset with 16-byte pattern. */

void memset_pattern16(void *dst, const void *pattern, size_t len) {
    const uint8_t *p = (const uint8_t *)pattern;
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < len; i += 16) {
        size_t chunk = (len - i < 16) ? (len - i) : 16;
        for (size_t j = 0; j < chunk; j++) {
            d[i + j] = p[j];
        }
    }
}
#include <dlfcn.h>

static void *libgcc_s_handle = NULL;

static void ensure_libgcc(void) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (!libgcc_s_handle) {
            libgcc_s_handle = dlopen("libgcc_s.so", RTLD_NOW | RTLD_GLOBAL);
        }
    }
}

/* The _Unwind_* functions have a standardized ABI (Itanium C++ ABI).
 * We forward to libgcc_s. If libgcc_s is not available, we use stubs. */

struct _Unwind_Exception;
struct _Unwind_Context;
typedef int (*_Unwind_Stop_Fn)(int, struct _Unwind_Exception *, struct _Unwind_Context *);

int _Unwind_Backtrace(_Unwind_Stop_Fn stop, void *stop_arg) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        int (*fn)(_Unwind_Stop_Fn, void *) = dlsym(libgcc_s_handle, "_Unwind_Backtrace");
        if (fn) return fn(stop, stop_arg);
    }
    return 5; /* _URC_END_OF_STACK */
}

void _Unwind_DeleteException(struct _Unwind_Exception *exc) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void (*fn)(struct _Unwind_Exception *) = dlsym(libgcc_s_handle, "_Unwind_DeleteException");
        if (fn) { fn(exc); return; }
    }
}

unsigned long _Unwind_GetIP(struct _Unwind_Context *ctx) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        unsigned long (*fn)(struct _Unwind_Context *) = dlsym(libgcc_s_handle, "_Unwind_GetIP");
        if (fn) return fn(ctx);
    }
    return 0;
}

unsigned long _Unwind_GetIPInfo(struct _Unwind_Context *ctx, int *ip_before_insn) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        unsigned long (*fn)(struct _Unwind_Context *, int *) = dlsym(libgcc_s_handle, "_Unwind_GetIPInfo");
        if (fn) return fn(ctx, ip_before_insn);
    }
    if (ip_before_insn) *ip_before_insn = 0;
    return 0;
}

void *_Unwind_GetLanguageSpecificData(struct _Unwind_Context *ctx) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void *(*fn)(struct _Unwind_Context *) = dlsym(libgcc_s_handle, "_Unwind_GetLanguageSpecificData");
        if (fn) return fn(ctx);
    }
    return NULL;
}

unsigned long _Unwind_GetRegionStart(struct _Unwind_Context *ctx) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        unsigned long (*fn)(struct _Unwind_Context *) = dlsym(libgcc_s_handle, "_Unwind_GetRegionStart");
        if (fn) return fn(ctx);
    }
    return 0;
}

void _Unwind_SetGR(struct _Unwind_Context *ctx, int index, unsigned long val) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void (*fn)(struct _Unwind_Context *, int, unsigned long) = dlsym(libgcc_s_handle, "_Unwind_SetGR");
        if (fn) { fn(ctx, index, val); return; }
    }
}

void _Unwind_SetIP(struct _Unwind_Context *ctx, unsigned long val) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void (*fn)(struct _Unwind_Context *, unsigned long) = dlsym(libgcc_s_handle, "_Unwind_SetIP");
        if (fn) { fn(ctx, val); return; }
    }
}

int _Unwind_RaiseException(struct _Unwind_Exception *exc) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        int (*fn)(struct _Unwind_Exception *) = dlsym(libgcc_s_handle, "_Unwind_RaiseException");
        if (fn) return fn(exc);
    }
    return 3; /* _URC_FATAL_PHASE1_ERROR */
}

void _Unwind_Resume(struct _Unwind_Exception *exc) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void (*fn)(struct _Unwind_Exception *) = dlsym(libgcc_s_handle, "_Unwind_Resume");
        if (fn) { fn(exc); return; }
    }
    abort();
}

int _Unwind_GetGR(struct _Unwind_Context *ctx, int index) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        int (*fn)(struct _Unwind_Context *, int) = dlsym(libgcc_s_handle, "_Unwind_GetGR");
        if (fn) return fn(ctx, index);
    }
    return 0;
}

unsigned long _Unwind_GetCFA(struct _Unwind_Context *ctx) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        unsigned long (*fn)(struct _Unwind_Context *) = dlsym(libgcc_s_handle, "_Unwind_GetCFA");
        if (fn) return fn(ctx);
    }
    return 0;
}

void *_Unwind_GetDataRelBase(struct _Unwind_Context *ctx) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void *(*fn)(struct _Unwind_Context *) = dlsym(libgcc_s_handle, "_Unwind_GetDataRelBase");
        if (fn) return fn(ctx);
    }
    return NULL;
}

void *_Unwind_GetTextRelBase(struct _Unwind_Context *ctx) {
    ensure_libgcc();
    if (libgcc_s_handle) {
        void *(*fn)(struct _Unwind_Context *) = dlsym(libgcc_s_handle, "_Unwind_GetTextRelBase");
        if (fn) return fn(ctx);
    }
    return NULL;
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

/* _CF* — minimal CoreFoundation stubs. */

void *CFBundleGetMainBundle(void) {
    return NULL;
}

void *CFBundleCopyBundleURL(void *bundle) {
    (void)bundle;
    return NULL;
}

void CFRelease(void *cf) {
    (void)cf;
}

/* CFString stubs — Rust's std library uses these for timezone lookup.
 * We return safe defaults so the caller doesn't crash. */

/* CFStringGetBytes: copy bytes from a CFString to a raw buffer.
 * Return 0 (failure) — the caller will fall back to CFStringGetCStringPtr. */
unsigned long CFStringGetBytes(void *theString, long rangeStart, long rangeLength,
                               unsigned long encoding,
                               unsigned char lossyByte, unsigned char isExternal,
                               unsigned char *bytes, unsigned long maxBytes,
                               long *usedBytes) {
    (void)theString; (void)rangeStart; (void)rangeLength;
    (void)encoding; (void)lossyByte; (void)isExternal;
    (void)bytes; (void)maxBytes;
    if (usedBytes) *usedBytes = 0;
    return 0;  /* 0 = conversion failed */
}

/* CFStringGetCStringPtr: return a direct C string pointer.
 * Return NULL — forces the caller to use CFStringGetBytes instead. */
const char *CFStringGetCStringPtr(void *theString, unsigned long encoding) {
    (void)theString; (void)encoding;
    return NULL;
}

/* CFStringGetLength: return the number of characters in a CFString.
 * Return 0 for our NULL/stub strings. */
long CFStringGetLength(void *theString) {
    (void)theString;
    return 0;
}

/* CFTimeZoneCopySystem: return a copy of the system timezone.
 * Return NULL — the caller should handle this gracefully. */
void *CFTimeZoneCopySystem(void) {
    return NULL;
}

/* CFTimeZoneGetName: return the name of a timezone.
 * Return NULL — the caller should handle this gracefully. */
const char *CFTimeZoneGetName(void *tz) {
    (void)tz;
    return NULL;
}

/* strlcpy / strlcat — BSD string functions not in older glibc.
 * macOS uses these extensively; glibc added them only in 2.38+. */
size_t strlcpy(char *dst, const char *src, size_t siz) {
    size_t len = strlen(src);
    if (siz > 0) {
        size_t copy = len < siz ? len : siz - 1;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return len;
}

size_t strlcat(char *dst, const char *src, size_t siz) {
    size_t dlen = strlen(dst);
    size_t slen = strlen(src);
    if (dlen >= siz) return slen + siz;
    size_t copy = (slen < siz - dlen) ? slen : siz - dlen - 1;
    memcpy(dst + dlen, src, copy);
    dst[dlen + copy] = '\0';
    return dlen + slen;
}

/* Fortified variants — just call the base functions */
size_t __strlcpy_chk(char *dst, const char *src, size_t siz, size_t dstlen) {
    (void)dstlen;
    return strlcpy(dst, src, siz);
}
size_t __strlcat_chk(char *dst, const char *src, size_t siz, size_t dstlen) {
    (void)dstlen;
    return strlcat(dst, src, siz);
}

/* macOS malloc zone API — sqlite3 and other C code use this.
 * We provide a proper malloc_zone_t struct with function pointers
 * that delegate to standard malloc/free/realloc.
 * Note: the exact layout depends on the macOS SDK version. Modern macOS
 * (10.6+) uses a layout where the first function pointer (malloc) is at
 * offset 0x10, with no separate 'size' field. */
struct _malloc_zone_t {
    void *reserved1;                                        /* 0x00 */
    void *reserved2;                                        /* 0x08 */
    void *(*malloc)(struct _malloc_zone_t *, size_t);       /* 0x10 */
    void *(*calloc)(struct _malloc_zone_t *, size_t, size_t); /* 0x18 */
    void *(*valloc)(struct _malloc_zone_t *, size_t);       /* 0x20 */
    void  (*free)(struct _malloc_zone_t *, void *);         /* 0x28 */
    void *(*realloc)(struct _malloc_zone_t *, void *, size_t); /* 0x30 */
    void  (*destroy)(struct _malloc_zone_t *);              /* 0x38 */
    const char *zone_name;                                  /* 0x40 */
    unsigned batch_malloc;                                  /* 0x48 */
    unsigned batch_free;                                    /* 0x4c */
    struct malloc_introspection_t *introspect;              /* 0x50 */
    void *reserved5;                                        /* 0x58 */
    void *reserved6;                                        /* 0x60 */
    void *reserved7;                                        /* 0x68 */
};

static void *zone_malloc(struct _malloc_zone_t *z, size_t s) { (void)z; return malloc(s); }
static void *zone_calloc(struct _malloc_zone_t *z, size_t n, size_t s) { (void)z; return calloc(n, s); }
static void *zone_valloc(struct _malloc_zone_t *z, size_t s) { (void)z; void *p = malloc(s); return p; }
static void  zone_free(struct _malloc_zone_t *z, void *p) { (void)z; free(p); }
static void *zone_realloc(struct _malloc_zone_t *z, void *p, size_t s) { (void)z; return realloc(p, s); }
static void  zone_destroy(struct _malloc_zone_t *z) { (void)z; }

static struct _malloc_zone_t macify_malloc_zone = {
    .reserved1 = NULL,
    .reserved2 = NULL,
    .malloc = zone_malloc,
    .calloc = zone_calloc,
    .valloc = zone_valloc,
    .free = zone_free,
    .realloc = zone_realloc,
    .destroy = zone_destroy,
    .zone_name = "macify",
};

void *malloc_default_zone(void) {
    return &macify_malloc_zone;
}
void *malloc_create_zone(size_t start, unsigned flags) {
    (void)start; (void)flags;
    return &macify_malloc_zone;
}
void malloc_set_zone_name(void *zone, const char *name) {
    (void)zone; (void)name;
}
size_t malloc_size(const void *ptr) {
    (void)ptr;
    return 0;
}
void *malloc_zone_malloc(void *zone, size_t size) {
    (void)zone;
    return malloc(size);
}
void *malloc_zone_realloc(void *zone, void *ptr, size_t size) {
    (void)zone;
    return realloc(ptr, size);
}
void malloc_zone_free(void *zone, void *ptr) {
    (void)zone;
    free(ptr);
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
void *CFArrayCreateMutable(void *alloc, long capacity, const void *cb) {
    (void)alloc; (void)capacity; (void)cb;
    return NULL;
}
void CFArrayAppendValue(void *array, const void *value) {
    (void)array; (void)value;
}
void *CFDataCreate(void *alloc, const void *bytes, long length) {
    (void)alloc; (void)bytes; (void)length;
    return NULL;
}
void *CFStringCreateWithCString(void *alloc, const char *cStr,
                                unsigned long encoding) {
    (void)alloc; (void)cStr; (void)encoding;
    return NULL;
}
int CFStringGetCString(void *theString, char *buffer, long bufferSize,
                       unsigned long encoding) {
    (void)theString; (void)encoding;
    if (buffer && bufferSize > 0) buffer[0] = '\0';
    return 0;
}
long CFStringGetMaximumSizeForEncoding(long length, unsigned long encoding) {
    (void)encoding;
    return length * 4 + 1;  /* worst case UTF-8 */
}
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

/* sysctl — macOS system information query. Rust uses this for CPU count,
 * memory size, hostname, etc. We implement common queries using Linux
 * equivalents and return -1 for unknown queries. */
#include <sys/utsname.h>

int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
           void *newp, size_t newlen) {
    (void)newp; (void)newlen;
    if (!name || namelen == 0) return -1;

    /* CTL_UNSPEC=0, CTL_KERN=1, CTL_HW=6, CTL_USER=8, CTL_VM=2 */
    int top = name[0];

    if (top == 6) {  /* CTL_HW */
        if (namelen < 2) return -1;
        int id = name[1];
        /* HW_NCPU=3, HW_MEMSIZE=24, HW_PAGESIZE=7 */
        if (id == 3) {  /* HW_NCPU */
            int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
            if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
                *(int *)oldp = ncpu;
                *oldlenp = sizeof(int);
            }
            return 0;
        }
        if (id == 24) {  /* HW_MEMSIZE */
            if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
                long pages = sysconf(_SC_PHYS_PAGES);
                long page_size = sysconf(_SC_PAGESIZE);
                *(uint64_t *)oldp = (uint64_t)pages * page_size;
                *oldlenp = sizeof(uint64_t);
            }
            return 0;
        }
        if (id == 7) {  /* HW_PAGESIZE */
            if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
                *(int *)oldp = (int)sysconf(_SC_PAGESIZE);
                *oldlenp = sizeof(int);
            }
            return 0;
        }
    }

    if (top == 1) {  /* CTL_KERN */
        if (namelen < 2) return -1;
        int id = name[1];
        /* KERN_OSTYPE=1, KERN_HOSTNAME=10, KERN_OSRELEASE=2 */
        if (id == 1 || id == 2) {  /* KERN_OSTYPE / KERN_OSRELEASE */
            struct utsname uts;
            uname(&uts);
            const char *val = (id == 1) ? "Darwin" : uts.release;
            size_t len = strlen(val) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp < len) return -1;  /* ENOMEM */
                strcpy((char *)oldp, val);
                *oldlenp = len;
            } else if (oldlenp) {
                *oldlenp = len;
            }
            return 0;
        }
        if (id == 10) {  /* KERN_HOSTNAME */
            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            size_t len = strlen(hostname) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp < len) return -1;
                strcpy((char *)oldp, hostname);
                *oldlenp = len;
            } else if (oldlenp) {
                *oldlenp = len;
            }
            return 0;
        }
    }

    /* Unknown sysctl — return -1 (errno will be ENOENT) */
    errno = ENOENT;
    return -1;
}

/* sysctlbyname — macOS variant that takes a string name instead of int array. */
int sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                 void *newp, size_t newlen) {
    (void)newp; (void)newlen;
    if (!name) return -1;

    /* Handle common Rust runtime queries */
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0) {
        int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int *)oldp = ncpu;
            *oldlenp = sizeof(int);
        }
        return 0;
    }
    if (strcmp(name, "hw.memsize") == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
            long pages = sysconf(_SC_PHYS_PAGES);
            long page_size = sysconf(_SC_PAGESIZE);
            *(uint64_t *)oldp = (uint64_t)pages * page_size;
            *oldlenp = sizeof(uint64_t);
        }
        return 0;
    }
    if (strcmp(name, "hw.pagesize") == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int *)oldp = (int)sysconf(_SC_PAGESIZE);
            *oldlenp = sizeof(int);
        }
        return 0;
    }

    errno = ENOENT;
    return -1;
}

/* sysctlnametomib — convert a sysctl name string to its MIB integer array.
 * We don't implement MIB lookup; return -1 (ENOENT). */
int sysctlnametomib(const char *name, int *mibp, size_t *sizep) {
    (void)name; (void)mibp; (void)sizep;
    errno = ENOENT;
    return -1;
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
    if (ucp) memset(ucp, 0, sizeof(*ucp));
    return 0;
}

int setcontext(const ucontext_t *ucp) {
    (void)ucp;
    errno = ENOSYS;
    return -1;
}

void makecontext(ucontext_t *ucp, void (*func)(void), int argc, ...) {
    (void)ucp; (void)func; (void)argc;
    /* no-op — async won't work but SSL_CTX_new should succeed */
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
 */
unsigned long __maskrune(unsigned long ch, unsigned long mask) {
    if (ch < 256) {
        return macify_runetype[ch] & mask;
    }
    return 0;
}

/* __isctype — another macOS classification helper */
#undef __isctype
int __isctype(int ch, unsigned long mask) {
    if (ch < 256) {
        return (macify_runetype[ch] & mask) != 0;
    }
    return 0;
}

/* __toupper / __tolower — macOS internal versions */
int __toupper(int ch) { return toupper(ch); }
int __tolower(int ch) { return tolower(ch); }

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

/* ── CoreFoundation stubs for htop ──────────────────────────────
 * htop uses CF functions for reading system configuration plist files.
 * We provide minimal stubs that return empty/null values. */

unsigned long CFGetTypeID(void *cf) {
    (void)cf;
    return 0;
}

unsigned long CFDictionaryGetTypeID(void) {
    return 0;
}

int CFNumberGetValue(void *number, unsigned int theType, void *valuePtr) {
    (void)number; (void)theType;
    if (valuePtr) memset(valuePtr, 0, 8);
    return 0;
}

void *CFPropertyListCreateWithStream(void *alloc, void *stream, long streamLength,
                                      char mutableAndReturnMutable, unsigned int options,
                                      void *format, void *error) {
    (void)alloc; (void)stream; (void)streamLength; (void)mutableAndReturnMutable;
    (void)options; (void)format; (void)error;
    return NULL;  /* no plist data */
}

void *CFReadStreamCreateWithFile(void *alloc, void *fileURL) {
    (void)alloc; (void)fileURL;
    return NULL;
}

int CFReadStreamOpen(void *stream) {
    (void)stream;
    return 0;
}

void CFReadStreamClose(void *stream) {
    (void)stream;
}

int CFStringCompare(void *theString1, void *theString2, unsigned int compareOptions) {
    (void)compareOptions;
    /* Compare as C strings if possible */
    return 0;
}

void *CFStringCreateWithFormat(void *alloc, void *formatOptions, const char *format, ...) {
    (void)alloc; (void)formatOptions; (void)format;
    return NULL;
}

void *CFURLCreateWithFileSystemPath(void *allocator, void *filePath, int pathStyle, int isDirectory) {
    (void)allocator; (void)filePath; (void)pathStyle; (void)isDirectory;
    return NULL;
}

/* kCFAllocatorDefault — macOS global. We provide a NULL pointer. */
void *kCFAllocatorDefault = NULL;

/* __CFConstantStringClassReference — macOS global for CFSTR() literals.
 * htop uses CFSTR() which creates constant CFString references.
 * We provide a dummy class. */
void *__CFConstantStringClassReference = NULL;

/* ── IOKit stubs for htop ───────────────────────────────────────
 * htop uses IOKit for power source info (battery). We stub these. */

void *kIOMainPortDefault = (void *)0;

void *IOServiceMatching(const char *name) {
    (void)name;
    return NULL;
}

void *IOServiceGetMatchingService(void *mainPort, void *matching) {
    (void)mainPort; (void)matching;
    return NULL;
}

int IOServiceGetMatchingServices(void *mainPort, void *matching, void *existing) {
    (void)mainPort; (void)matching; (void)existing;
    return 0;  /* kIOReturnSuccess but no iterators */
}

int IOIteratorNext(void *iterator) {
    (void)iterator;
    return 0;  /* no more objects */
}

void IOObjectRelease(void *obj) {
    (void)obj;
}

int IORegistryEntryCreateCFProperties(void *entry, void *props, void *alloc, unsigned int options) {
    (void)entry; (void)props; (void)alloc; (void)options;
    return 0;
}

void *IORegistryEntryCreateCFProperty(void *entry, void *key, void *alloc, unsigned int options) {
    (void)entry; (void)key; (void)alloc; (void)options;
    return NULL;
}

/* IOKit power source stubs */
void *IOPSCopyPowerSourcesInfo(void) {
    return NULL;
}

void *IOPSCopyPowerSourcesList(void *blob) {
    (void)blob;
    return NULL;  /* empty array */
}

void *IOPSGetPowerSourceDescription(void *blob, void *ps) {
    (void)blob; (void)ps;
    return NULL;
}
