/* cf.c — CoreFoundation and SystemConfiguration stubs */
#include "../shim.h"

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
void *macify_CFStringCreateWithCString(void *alloc, const char *cstr, unsigned int encoding) __asm__("CFStringCreateWithCString");
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
int macify_CFStringGetCString(const void *cfstr, char *buf, long buf_size, unsigned int encoding) __asm__("CFStringGetCString");
int macify_CFStringGetCString(const void *cfstr, char *buf, long buf_size, unsigned int encoding) {
    (void)encoding;
    if (!cfstr || !buf || buf_size <= 0) return 0;
    const struct sc_obj *s = (const struct sc_obj *)cfstr;
    if (s->tag != SC_TAG_STRING) return 0;
    strncpy(buf, (const char *)s->data, buf_size - 1);
    buf[buf_size - 1] = '\0';
    return 1;
}

long macify_CFStringGetLength(const void *cfstr) __asm__("CFStringGetLength");
long macify_CFStringGetLength(const void *cfstr) {
    if (!cfstr) return 0;
    const struct sc_obj *s = (const struct sc_obj *)cfstr;
    if (s->tag != SC_TAG_STRING) return 0;
    return (long)s->count;
}

long macify_CFStringGetMaximumSizeForEncoding(long length, unsigned int encoding) __asm__("CFStringGetMaximumSizeForEncoding");
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

/* CFTimeZoneCopySystem: return NULL — the caller handles gracefully. */
void *CFTimeZoneCopySystem(void) { return NULL; }

/* CFTimeZoneGetName: return the name of a timezone.
 * Return NULL — the caller should handle this gracefully. */
const char *CFTimeZoneGetName(void *tz) {
    (void)tz;
    return NULL;
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

/* kCFAllocatorNull — a special allocator that never allocates (always returns NULL).
 * Some CF functions check for this to skip allocation. We provide a sentinel. */
static char cf_alloc_null_sentinel[16] = {0};
void *kCFAllocatorNull = cf_alloc_null_sentinel;

/* __CFConstantStringClassReference — macOS global for CFSTR() literals.
 * htop uses CFSTR() which creates constant CFString references.
 * We provide a dummy class. */
void *__CFConstantStringClassReference = NULL;

/* ── DNS configuration stubs ──────────────────────────────────── */

void *macify_dns_configuration_copy(void) {
    return NULL;
}

void macify_dns_configuration_free(void *config) {
    (void)config;
}

/* ── CFArray/CFData stubs (curl, sqlite3, dust use these) ── */

void *CFArrayCreateMutable(void *alloc, long cap, const void *cb) {
    (void)alloc; (void)cap; (void)cb;
    return NULL;
}

void CFArrayAppendValue(void *arr, const void *val) {
    (void)arr; (void)val;
}

void *CFDataCreate(void *alloc, const void *bytes, long length) {
    (void)alloc; (void)length;
    return bytes ? (void *)bytes : NULL;
}

/* CFDataGetLength — return the length of a CFData.
 * Since our CFDataCreate returns the raw bytes pointer, we can't know
 * the length. Return 0 as a safe default. */
long CFDataGetLength(const void *data) {
    (void)data;
    return 0;
}

/* CFDataGetBytes — see cf_compat.c (avoids system header conflict) */

/* CFDataGetBytePtr — return pointer to the bytes. Since our CFData
 * IS the bytes pointer, just return it. */
const void *CFDataGetBytePtr(const void *data) {
    return data;
}

/* CFDataCreateMutable — create a mutable CFData. Return NULL. */
void *CFDataCreateMutable(void *alloc, long cap) {
    (void)alloc; (void)cap;
    return NULL;
}

/* CFDataCreateMutableCopy — copy a CFData. Return NULL. */
void *CFDataCreateMutableCopy(void *alloc, long cap, const void *data) {
    (void)alloc; (void)cap; (void)data;
    return NULL;
}

/* CFDataAppendBytes — append bytes to a mutable CFData. No-op. */
void CFDataAppendBytes(void *data, const void *bytes, long length) {
    (void)data; (void)bytes; (void)length;
}

/* CFDictionaryCreateMutable — create a mutable CFDictionary. Return NULL. */
void *CFDictionaryCreateMutable(void *alloc, long cap, const void *keyCb, const void *valCb) {
    (void)alloc; (void)cap; (void)keyCb; (void)valCb;
    return NULL;
}

/* CFDictionarySetValue — set a key-value pair. No-op. */
void CFDictionarySetValue(void *dict, const void *key, const void *val) {
    (void)dict; (void)key; (void)val;
}

/* CFDictionaryAddValue — add a key-value pair. No-op. */
void CFDictionaryAddValue(void *dict, const void *key, const void *val) {
    (void)dict; (void)key; (void)val;
}

/* CFDictionaryGetCount — return number of entries. */
long CFDictionaryGetCount(const void *dict) {
    (void)dict;
    return 0;
}

/* CFDictionaryApplyFunction — iterate over entries. No-op. */
void CFDictionaryApplyFunction(const void *dict, void *func, void *context) {
    (void)dict; (void)func; (void)context;
}

/* CFNumberCreate — create a CFNumber. Return NULL. */
void *CFNumberCreate(void *alloc, int type, const void *valuePtr) {
    (void)alloc; (void)type; (void)valuePtr;
    return NULL;
}

/* CFNumberGetValue, CFGetTypeID, CFStringCreateWithFormat, CFStringGetCStringPtr
 * conflict with system CoreFoundation headers. These are implemented in
 * cf_compat.c which avoids including system headers. */

/* CFArrayCreate — create an immutable CFArray. Return NULL. */
void *CFArrayCreate(void *alloc, const void **values, long numValues, const void *cb) {
    (void)alloc; (void)values; (void)numValues; (void)cb;
    return NULL;
}

/* CFRetain — retain a CF object. No-op (return the object). */
const void *CFRetain(const void *cf) {
    return cf;
}

/* CFShow — print a CF object to stderr. No-op. */
void CFShow(const void *cf) {
    (void)cf;
}

/* CFCopyDescription — return a description string. Return NULL. */
void *CFCopyDescription(const void *cf) {
    (void)cf;
    return NULL;
}

/* CFEqual — compare two CF objects. */
int CFEqual(const void *cf1, const void *cf2) {
    return cf1 == cf2;
}

/* CFHash — hash a CF object. */
unsigned long CFHash(const void *cf) {
    return (unsigned long)(uintptr_t)cf;
}

/* CFGetRetainCount — return retain count. */
long CFGetRetainCount(const void *cf) {
    (void)cf;
    return 1;
}

/* CFStringCreateWithCStringNoCopy — create a CFString without copying. */
void *CFStringCreateWithCStringNoCopy(void *alloc, const char *cStr, int encoding, void *contentsDeallocator) {
    (void)alloc; (void)encoding; (void)contentsDeallocator;
    return (void *)cStr;  /* just return the C string pointer */
}

/* CFStringCreateWithFormat, CFStringGetCStringPtr — see cf_compat.c */

/* CFStringGetSystemEncoding — return the system encoding. */
int CFStringGetSystemEncoding(void) {
    return 0x0600;  /* kCFStringEncodingUTF8 */
}

/* CFStringGetFastestEncoding — return the fastest encoding. */
int CFStringGetFastestEncoding(const void *str) {
    (void)str;
    return 0x0600;  /* kCFStringEncodingUTF8 */
}
