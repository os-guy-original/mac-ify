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

/* Tag values for our fake CF objects. Also defined in shim.h for use
 * by other shim files (objc_compat.c, etc.). */
#define SC_TAG_STRING     0x5C01  /* fake CFString */
#define SC_TAG_ARRAY      0x5C02  /* fake CFArray */
#define SC_TAG_DICT       0x5C03  /* fake CFDictionary */
#define SC_TAG_STORE      0x5C04  /* fake SCDynamicStoreRef */

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
    } else if (o->tag == SC_TAG_DATA) {
        free(o->data);
    } else if (o->tag == SC_TAG_BOOL || o->tag == SC_TAG_NULL) {
        /* No payload to free — just free the object */
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

/* CFDictionaryGetValueIfPresent — like GetValue but returns whether key was found. */
int macify_CFDictionaryGetValueIfPresent(const void *dict, const void *key, const void **value) __asm__("CFDictionaryGetValueIfPresent");
int macify_CFDictionaryGetValueIfPresent(const void *dict, const void *key, const void **value) {
    const void *val = macify_CFDictionaryGetValue(dict, key);
    if (value) *value = val;
    return val != NULL;
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
 * Works with our sc_obj-tagged strings (created by CFStringCreateWithBytesNoCopy,
 * CFStringCreateWithCString, etc.). Returns the number of bytes actually copied
 * into `bytes`. 0 = conversion failed or empty string. */
unsigned long CFStringGetBytes(void *theString, long rangeStart, long rangeLength,
                               unsigned long encoding,
                               unsigned char lossyByte, unsigned char isExternal,
                               unsigned char *bytes, unsigned long maxBytes,
                               long *usedBytes) {
    (void)encoding; (void)lossyByte; (void)isExternal;
    if (!theString) { if (usedBytes) *usedBytes = 0; return 0; }
    const struct sc_obj *s = (const struct sc_obj *)theString;
    if (s->tag != SC_TAG_STRING) { if (usedBytes) *usedBytes = 0; return 0; }
    const char *src = (const char *)s->data;
    if (!src) { if (usedBytes) *usedBytes = 0; return 0; }
    long total = (long)s->count;
    /* Clip range to actual string length */
    if (rangeStart < 0) rangeStart = 0;
    if (rangeLength < 0) rangeLength = 0;
    if (rangeStart > total) rangeStart = total;
    if (rangeStart + rangeLength > total) rangeLength = total - rangeStart;
    if (rangeLength == 0) { if (usedBytes) *usedBytes = 0; return 0; }
    /* Copy as many bytes as fit in `bytes` */
    unsigned long to_copy = (unsigned long)rangeLength;
    if (maxBytes < to_copy) to_copy = maxBytes;
    if (bytes && to_copy > 0) memcpy(bytes, src + rangeStart, to_copy);
    if (usedBytes) *usedBytes = (long)to_copy;
    return to_copy;
}

/* CFStringGetCStringPtr: return a direct C string pointer.
 * For our sc_obj-tagged strings, we can return the underlying buffer directly. */
const char *CFStringGetCStringPtr(void *theString, unsigned long encoding) {
    (void)encoding;
    if (!theString) return NULL;
    const struct sc_obj *s = (const struct sc_obj *)theString;
    if (s->tag != SC_TAG_STRING) return NULL;
    return (const char *)s->data;
}

/* CFTimeZoneCopySystem: return NULL — the caller handles gracefully. */
void *CFTimeZoneCopySystem(void) { return NULL; }

/* CFTimeZoneGetName: return the name of a timezone.
 * Return NULL — the caller should handle this gracefully. */
const char *CFTimeZoneGetName(void *tz) {
    (void)tz;
    return NULL;
}

/* CFTimeZoneResetSystem — no-op (we don't cache anything). */
void CFTimeZoneResetSystem(void) {
}

/* CFStringCreateWithBytesNoCopy — create a CFString from a raw byte buffer
 * WITHOUT copying the bytes (the caller owns the buffer; the allocator
 * releaseFn is responsible for freeing it). Used by Rust std's macOS
 * platform code for string interop.
 *
 * We wrap the bytes in an sc_obj with tag=SC_TAG_STRING so that
 * CFStringGetBytes, CFStringGetCStringPtr, CFStringGetLength can work
 * on it. Note: we DO NOT take ownership of `bytes`; the caller must
 * keep it alive for the lifetime of the returned CFStringRef. */
void *macify_CFStringCreateWithBytesNoCopy(void *alloc, const void *bytes,
                                            long numBytes, unsigned long encoding,
                                            unsigned char shouldFreeBytes) __asm__("CFStringCreateWithBytesNoCopy");
void *macify_CFStringCreateWithBytesNoCopy(void *alloc, const void *bytes,
                                            long numBytes, unsigned long encoding,
                                            unsigned char shouldFreeBytes) {
    (void)alloc; (void)encoding; (void)shouldFreeBytes;
    if (!bytes && numBytes > 0) return NULL;
    struct sc_obj *s = (struct sc_obj *)calloc(1, sizeof(*s));
    s->tag = SC_TAG_STRING;
    s->count = (uint32_t)numBytes;
    s->data = (void *)bytes;  /* no copy — caller-owned */
    return s;
}


/* ── CF type IDs ───────────────────────────────────────────────
 * CoreFoundation's CFGetTypeID(obj) returns a unique integer per CF type.
 * Real macOS uses an internal registry; we simulate with small constants.
 * Objects created by our shim carry an sc_obj tag (SC_TAG_STRING, etc.),
 * so CFGetTypeID dispatches on that. Objects NOT created by our shim
 * (e.g. raw pointers from CFDataCreate which returns the bytes pointer)
 * fall through to a default "unknown" type ID. */
#define CF_TYPEID_STRING   0x53747267  /* 'Strg' */
#define CF_TYPEID_ARRAY    0x41727261  /* 'Arra' */
#define CF_TYPEID_DICT     0x44696374  /* 'Dict' */
#define CF_TYPEID_DATA     0x44617461  /* 'Data' */
#define CF_TYPEID_NUMBER   0x4e756d62  /* 'Numb' */
#define CF_TYPEID_URL      0x55524c5f  /* 'URL_' */
#define CF_TYPEID_UNKNOWN  0

unsigned long CFGetTypeID(void *cf) {
    /* Check for NULL or obviously invalid pointers.
     * macOS code sometimes passes -1 (0xffffffffffffffff) or other
     * garbage values from failed function calls. Without this check,
     * dereferencing the pointer crashes. */
    if (!cf || (uintptr_t)cf < 0x10000 || (uintptr_t)cf > 0x7fffffffffffUL)
        return CF_TYPEID_UNKNOWN;
    const struct sc_obj *o = (const struct sc_obj *)cf;
    switch (o->tag) {
        case SC_TAG_STRING: return CF_TYPEID_STRING;
        case SC_TAG_ARRAY:  return CF_TYPEID_ARRAY;
        case SC_TAG_DICT:   return CF_TYPEID_DICT;
        case SC_TAG_STORE:  return CF_TYPEID_UNKNOWN;
        default:            return CF_TYPEID_UNKNOWN;
    }
}

unsigned long CFStringGetTypeID(void) { return CF_TYPEID_STRING; }
unsigned long CFArrayGetTypeID(void)  { return CF_TYPEID_ARRAY; }
unsigned long CFDataGetTypeID(void)   { return CF_TYPEID_DATA; }
unsigned long CFNumberGetTypeID(void) { return CF_TYPEID_NUMBER; }
unsigned long CFURLGetTypeID(void)    { return CF_TYPEID_URL; }

unsigned long CFDictionaryGetTypeID(void) {
    return CF_TYPEID_DICT;
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
    (void)alloc;
    if (!bytes && length > 0) return NULL;
    struct sc_obj *d = (struct sc_obj *)calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->tag = SC_TAG_DATA;
    d->count = (uint32_t)length;
    if (length > 0) {
        d->data = malloc(length);
        if (d->data) memcpy(d->data, bytes, length);
    }
    return d;
}

/* CFDataGetLength — return the length of a CFData. */
long CFDataGetLength(const void *data) {
    if (!data) return 0;
    struct sc_obj *o = (struct sc_obj *)data;
    return (o->tag == SC_TAG_DATA) ? (long)o->count : 0;
}

/* CFDataGetBytes — see cf_compat.c (avoids system header conflict) */

/* CFDataGetBytePtr — return pointer to the bytes. */
const void *CFDataGetBytePtr(const void *data) {
    if (!data) return NULL;
    struct sc_obj *o = (struct sc_obj *)data;
    return (o->tag == SC_TAG_DATA) ? o->data : NULL;
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

/* CFStringCreateWithCStringNoCopy — create a CFString without copying.
 * Returns a proper sc_obj wrapper pointing to the original C string. */
void *CFStringCreateWithCStringNoCopy(void *alloc, const char *cStr, int encoding, void *contentsDeallocator) {
    (void)alloc; (void)encoding; (void)contentsDeallocator;
    if (!cStr) return NULL;
    struct sc_obj *s = (struct sc_obj *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->tag = SC_TAG_STRING;
    s->count = (uint32_t)strlen(cStr);
    s->data = (void *)cStr;  /* no copy — points to caller's buffer */
    return s;
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

/* Additional CF stubs for Rust binaries */
void CFArrayInsertValueAtIndex(void *array, long idx, const void *value) {
    (void)array; (void)idx; (void)value;
}

static void *kCFRunLoopDefaultMode_ptr = (void *)1;
void *kCFRunLoopDefaultMode = &kCFRunLoopDefaultMode_ptr;
void *kCFRunLoopCommonModes = &kCFRunLoopDefaultMode_ptr;

void CFArrayRemoveValueAtIndex(void *array, long idx) {
    (void)array; (void)idx;
}

void *CFArrayCreateMutableCopy(void *allocator, long capacity, void *srcArray) {
    (void)allocator; (void)capacity; (void)srcArray;
    return NULL;
}

void CFArrayRemoveAllValues(void *array) {
    (void)array;
}

void *CFSetCreateMutable(void *allocator, long capacity, const void *cb) {
    (void)allocator; (void)capacity; (void)cb;
    return NULL;
}

void CFSetAddValue(void *set, const void *value) {
    (void)set; (void)value;
}

void *CFRunLoopSourceCreate(void *allocator, long order, void *context) {
    (void)allocator; (void)order; (void)context;
    return NULL;
}

void CFRunLoopAddSource(void *rl, void *source, void *mode) {
    (void)rl; (void)source; (void)mode;
}

void CFRunLoopRemoveSource(void *rl, void *source, void *mode) {
    (void)rl; (void)source; (void)mode;
}

void CFRunLoopRun(void) {}
void CFRunLoopStop(void *rl) { (void)rl; }
void *CFRunLoopGetCurrent(void) { return NULL; }
void *CFRunLoopGetMain(void) { return NULL; }

void CFRunLoopAddTimer(void *rl, void *timer, void *mode) {
    (void)rl; (void)timer; (void)mode;
}

void CFRunLoopRemoveTimer(void *rl, void *timer, void *mode) {
    (void)rl; (void)timer; (void)mode;
}

void *CFRunLoopTimerCreate(void *allocator, double fireDate, double interval, long flags, long order, void *callout, void *context) {
    (void)allocator; (void)fireDate; (void)interval; (void)flags; (void)order; (void)callout; (void)context;
    return NULL;
}

void CFRunLoopTimerInvalidate(void *timer) { (void)timer; }

void *CFRunLoopObserverCreate(void *allocator, long activities, long repeats, long order, void *callout, void *context) {
    (void)allocator; (void)activities; (void)repeats; (void)order; (void)callout; (void)context;
    return NULL;
}

void CFRunLoopAddObserver(void *rl, void *observer, void *mode) {
    (void)rl; (void)observer; (void)mode;
}

/* CFURL stubs for watchexec */
void *CFURLCreateCopyDeletingLastPathComponent(void *alloc, void *url) {
    (void)alloc; (void)url;
    return NULL;
}

void *CFURLCopyAbsoluteURL(void *url) {
    (void)url;
    return NULL;
}

void *CFURLCopyFileSystemPath(void *url, int pathStyle) {
    (void)url; (void)pathStyle;
    return NULL;
}

void *CFURLCopyLastPathComponent(void *url) {
    (void)url;
    return NULL;
}

void *CFURLCreateCopyAppendingPathComponent(void *alloc, void *url, void *component, int isDirectory) {
    (void)alloc; (void)url; (void)component; (void)isDirectory;
    return NULL;
}


void *CFURLCreateFromFileSystemRepresentation(void *alloc, const char *buffer, long bufSize, int isDirectory) {
    (void)alloc; (void)buffer; (void)bufSize; (void)isDirectory;
    return NULL;
}

int CFURLGetFileSystemRepresentation(void *url, int resolveAgainstBase, char *buffer, long maxBufSize) {
    (void)url; (void)resolveAgainstBase;
    if (buffer && maxBufSize > 0) buffer[0] = '\0';
    return 0;
}

int CFURLIsFileURL(void *url) {
    (void)url;
    return 0;
}

void *CFURLCreateWithString(void *alloc, void *string, void *baseURL) {
    (void)alloc; (void)string; (void)baseURL;
    return NULL;
}

int CFRunLoopIsWaiting(void *rl) {
    (void)rl;
    return 0;
}

void *CFBundleGetValueForInfoDictionaryKey(void *bundle, void *key) {
    (void)bundle; (void)key;
    return NULL;
}

void *CFURLCreateFilePathURL(void *alloc, void *url, void *pathStyle) {
    (void)alloc; (void)url; (void)pathStyle;
    return NULL;
}

void *CFURLCreateStringByAddingPercentEscapes(void *alloc, void *originalString, void *legalCharactersToBeEscaped, void *legalCharactersToLeaveUnescaped, void *encoding) {
    (void)alloc; (void)originalString; (void)legalCharactersToBeEscaped; (void)legalCharactersToLeaveUnescaped; (void)encoding;
    return NULL;
}

void *CFURLCreateStringByReplacingPercentEscapes(void *alloc, void *originalString, void *charactersToLeave) {
    (void)alloc; (void)originalString; (void)charactersToLeave;
    return NULL;
}

void *CFURLCreateFileReferenceURL(void *alloc, void *url, void *isStale) {
    (void)alloc; (void)url; (void)isStale;
    return NULL;
}

void *CFURLCreateByResolvingAliasFile(void *alloc, void *url, unsigned int options, void *isStale) {
    (void)alloc; (void)url; (void)options; (void)isStale;
    return NULL;
}

int CFURLStartAccessingResourcePath(void *url) {
    (void)url;
    return 1;
}

void CFURLStopAccessingResourcePath(void *url) {
    (void)url;
}

void *CFURLCreateBookmarkData(void *alloc, void *url, unsigned int options, void *resourceProperties, void *relativeURL, void *error) {
    (void)alloc; (void)url; (void)options; (void)resourceProperties; (void)relativeURL; (void)error;
    return NULL;
}

void *CFURLCreateBookmarkDataFromFile(void *alloc, void *fileURL, void *error) {
    (void)alloc; (void)fileURL; (void)error;
    return NULL;
}

int CFURLWriteBookmarkDataToFile(void *bookmarkRef, void *fileURL, unsigned int options, void *error) {
    (void)bookmarkRef; (void)fileURL; (void)options; (void)error;
    return 0;
}

void *CFURLCreateResourcePropertyFromAbsoluteURL(void *alloc, void *url, void *key, void *error) {
    (void)alloc; (void)url; (void)key; (void)error;
    return NULL;
}

void *CFURLCopyResourcePropertiesForKeys(void *url, void *keys, void *error) {
    (void)url; (void)keys; (void)error;
    return NULL;
}

void *CFURLCopyResourcePropertyForKey(void *url, void *key, void *error) {
    (void)url; (void)key; (void)error;
    return NULL;
}

int CFURLSetResourcePropertyForKey(void *url, void *key, void *value, void *error) {
    (void)url; (void)key; (void)value; (void)error;
    return 0;
}

void *CFURLCreateResourcePropertiesFromAbsoluteURL(void *alloc, void *url, void *keys, void *error) {
    (void)alloc; (void)url; (void)keys; (void)error;
    return NULL;
}

void *CFURLCreateTemporaryDirectory(void *alloc, void *properties, void *error) {
    (void)alloc; (void)properties; (void)error;
    return NULL;
}

int CFURLIsFileReferenceURL(void *url) {
    (void)url;
    return 0;
}

void *CFURLCreateDirectoryAtURL(void *url, int createIntermediates, void *attributes, void *error) {
    (void)url; (void)createIntermediates; (void)attributes; (void)error;
    return NULL;
}

void *CFURLCreateFileAtURL(void *url, int createIntermediates, void *attributes, void *error) {
    (void)url; (void)createIntermediates; (void)attributes; (void)error;
    return NULL;
}

int CFURLDestroyDirectory(void *url, void *error) {
    (void)url; (void)error;
    return 0;
}

int CFURLDestroyFile(void *url, void *error) {
    (void)url; (void)error;
    return 0;
}

void *CFURLCreatePropertyFromAbsoluteURL(void *alloc, void *url, void *key, void *error) {
    (void)alloc; (void)url; (void)key; (void)error;
    return NULL;
}
int CFURLResourceIsReachable(void *url, void *error) { (void)url; (void)error; return 1; }
void FSEventStreamCreate(void) {}
void FSEventStreamGetDeviceBeingWatched(void) {}
void FSEventStreamInvalidate(void) {}
void FSEventStreamRelease(void) {}
void FSEventStreamScheduleWithRunLoop(void) {}
void FSEventStreamStart(void) {}
void FSEventStreamStop(void) {}
void FSEventsGetCurrentEventId(void) {}
void FSEventsPurgeEventsForDeviceUpToEventId(void) {}
void objc_setProperty_nonatomic(void) {}
