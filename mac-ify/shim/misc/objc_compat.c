/* objc_compat.c — Objective-C runtime + CF/AppKit/Foundation stubs.
 *
 * This file provides:
 *   - OBJC_CLASS_$_* / OBJC_METACLASS_$_* global class pointers
 *   - objc_* runtime functions (objc_alloc, objc_retain, etc.)
 *   - class_* / object_* / sel_* / method_* runtime functions
 *   - _Block_object_assign / _Block_object_dispose
 *   - dispatch_once
 *   - _objc_empty_cache / _objc_empty_vtable
 *   - Additional CF stubs (CFBoolean*, CFStringCreateWithBytes)
 *   - LaunchServices stubs (LSCopyApplicationURLsForBundleIdentifier)
 *   - IOMasterPort function
 *   - NSDefaultRunLoopMode / NSUserNotificationDefaultSoundName globals
 *
 * These are needed by Rust binaries (starship, etc.) that use macOS
 * Cocoa/AppKit/Foundation frameworks viaobjc bridges. We provide
 * minimal stubs so the binary loads and runs its main code path;
 * features that require actual AppKit behavior (notifications, etc.)
 * will silently no-op.
 */
#include "../shim.h"
#include <string.h>

/* ── objc_class sentinel ──────────────────────────────────────────
 * macOS OBJC_CLASS_$_* symbols point to a `struct objc_class` with
 * isa, superclass, cache, vtable, etc. We provide a zeroed sentinel
 * struct; objc_msgSend (in shim_objc.c) returns NULL regardless. */
struct macify_objc_class {
    void *isa;            /* metaclass pointer */
    void *superclass;     /* parent class */
    void *cache;          /* method cache */
    void *vtable;         /* vtable */
    void *data;           /* class info */
    void *reserved[3];    /* padding */
};

/* Sentinel for all OBJC_CLASS_$_* symbols — they all point here.
 * Each one gets its own exported symbol so the loader can bind them,
 * but the underlying data is the same sentinel. */
static struct macify_objc_class macify_objc_class_sentinel = {0};

/* Each of these is a *pointer* to a class object (not the class itself),
 * matching macOS ABI: `extern struct objc_class *OBJC_CLASS_$_NSObject;` */
#define DEFINE_OBJC_CLASS(name) \
    void *name = &macify_objc_class_sentinel

DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSObject);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSString);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSNumber);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSData);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSDate);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSURL);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSBundle);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSAppleScript);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSImage);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSThread);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSUUID);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSUserNotification);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSUserNotificationCenter);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSRunLoop);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSTimer);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSArray);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSMutableArray);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSDictionary);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSMutableDictionary);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSError);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSProcessInfo);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSEnumerator);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSNotification);
DEFINE_OBJC_CLASS(OBJC_CLASS_$_NSNotificationCenter);

/* OBJC_METACLASS_$_NSObject — metaclass for NSObject. Same sentinel. */
DEFINE_OBJC_CLASS(OBJC_METACLASS_$_NSObject);

/* _objc_empty_cache / _objc_empty_vtable — libobjc globals.
 * Used as default values for class->cache and class->vtable. */
static char macify_objc_empty_cache[16] = {0};
static char macify_objc_empty_vtable[16] = {0};
void *_objc_empty_cache = macify_objc_empty_cache;
void *_objc_empty_vtable = macify_objc_empty_vtable;

/* ── objc_* runtime functions ─────────────────────────────────── */

/* objc_alloc — allocates a new instance of a class. We return NULL
 * (allocation failed); callers should handle this gracefully. */
void *objc_alloc(void *cls) {
    (void)cls;
    return NULL;
}

/* objc_autoreleasePoolPush / Pop — ARC autorelease pool management.
 * Push returns a sentinel "pool" pointer; Pop ignores it. */
void *objc_autoreleasePoolPush(void) {
    return (void *)1;  /* non-NULL sentinel */
}

void objc_autoreleasePoolPop(void *pool) {
    (void)pool;
}

/* objc_retain / Release — ARC reference counting. No-op (return self). */
void *objc_retain(void *obj) { return obj; }
void objc_release(void *obj) { (void)obj; }

/* objc_retainAutoreleasedReturnValue — ARC optimization. No-op. */
void *objc_retainAutoreleasedReturnValue(void *obj) { return obj; }

/* objc_autorelease — no-op. */
void *objc_autorelease(void *obj) { return obj; }

/* objc_enumerationMutation — called during fast enumeration when the
 * collection is mutated. We no-op (no enumeration safety). */
void objc_enumerationMutation(void *obj) { (void)obj; }

/* ── class_* runtime functions ────────────────────────────────── */

/* class_getInstanceMethod — return NULL (method not found). */
void *class_getInstanceMethod(void *cls, void *sel) {
    (void)cls; (void)sel;
    return NULL;
}

/* class_getClassMethod — return NULL. */
void *class_getClassMethod(void *cls, void *sel) {
    (void)cls; (void)sel;
    return NULL;
}

/* class_getName — return a static empty string. */
const char *class_getName(void *cls) {
    (void)cls;
    return "";
}

/* class_isMetaClass — return 0 (false). */
int class_isMetaClass(void *cls) {
    (void)cls;
    return 0;
}

/* class_getSuperclass — return NULL. */
void *class_getSuperclass(void *cls) {
    (void)cls;
    return NULL;
}

/* class_addMethod — return NO (failed). */
int class_addMethod(void *cls, void *sel, void *imp, const char *types) {
    (void)cls; (void)sel; (void)imp; (void)types;
    return 0;
}

/* class_respondsToSelector — return NO. */
int class_respondsToSelector(void *cls, void *sel) {
    (void)cls; (void)sel;
    return 0;
}

/* ── object_* runtime functions ───────────────────────────────── */

/* object_getClass — return the class of an object. Return NULL. */
void *object_getClass(void *obj) {
    (void)obj;
    return NULL;
}

/* object_setClass — return the old class (NULL). */
void *object_setClass(void *obj, void *cls) {
    (void)obj; (void)cls;
    return NULL;
}

/* object_getClassName — return empty string. */
const char *object_getClassName(void *obj) {
    (void)obj;
    return "";
}

/* ── sel_* runtime functions ──────────────────────────────────── */

/* sel_getName — return the selector name (selector is just a string pointer). */
const char *sel_getName(void *sel) {
    return sel ? (const char *)sel : "";
}

/* sel_registerName — register a selector; return the string as the selector. */
void *sel_registerName(const char *name);

/* sel_isEqual — compare two selectors. */
int sel_isEqual(void *sel1, void *sel2) {
    return sel1 == sel2;
}

/* ── method_* runtime functions ───────────────────────────────── */

/* method_exchangeImplementations — swizzle two methods. No-op. */
void method_exchangeImplementations(void *method1, void *method2) {
    (void)method1; (void)method2;
}

/* method_getImplementation — return NULL. */
void *method_getImplementation(void *method) {
    (void)method;
    return NULL;
}

/* method_setImplementation — return old implementation (NULL). */
void *method_setImplementation(void *method, void *imp) {
    (void)method; (void)imp;
    return NULL;
}

/* ── Block runtime helpers ──────────────────────────────────────
 * _Block_object_assign and _Block_object_dispose are called when
 * blocks capture Objective-C objects. We no-op since we don't have
 * a real Block runtime. */
void _Block_object_assign(void *destAddr, const void *object, const int flags) {
    (void)destAddr; (void)object; (void)flags;
}

void _Block_object_dispose(const void *object, const int flags) {
    (void)object; (void)flags;
}

/* _Block_copy / _Block_release — block memory management.
 * Return the block as-is (no copy/free). */
void *_Block_copy(const void *aBlock) {
    return (void *)aBlock;
}

void _Block_release(const void *aBlock) {
    (void)aBlock;
}

/* ── dispatch_once ──────────────────────────────────────────────
 * GCD one-shot initialization. We use pthread_once for the actual
 * once-semantics. */
void dispatch_once(void **predicate, void (*block)(void)) {
    static pthread_mutex_t once_lock = PTHREAD_MUTEX_INITIALIZER;
    if (!predicate || !block) return;
    pthread_mutex_lock(&once_lock);
    if (!*predicate) {
        *predicate = (void *)1;
        pthread_mutex_unlock(&once_lock);
        block();
    } else {
        pthread_mutex_unlock(&once_lock);
    }
}

/* dispatch_get_global_queue — return a sentinel queue. */
void *dispatch_get_global_queue(long identifier, unsigned long flags) {
    (void)identifier; (void)flags;
    static char global_queue_sentinel[64] = {0};
    return global_queue_sentinel;
}

/* dispatch_after — schedule a block after a delay. We just call it
 * synchronously (since we have no real GCD timer). */
void dispatch_after(unsigned long when, void *queue, void *block) {
    (void)when; (void)queue;
    if (block) {
        typedef void (*block_fn)(void);
        block_fn fn = *(block_fn *)block;  /* block first 8 bytes = invoke fn */
        if (fn) fn();
    }
}

/* dispatch_async_f — schedule a C function on a queue. Run synchronously. */
void dispatch_async_f(void *queue, void *context, void (*function)(void *)) {
    (void)queue;
    if (function) function(context);
}

/* dispatch_sync_f — run a C function synchronously. */
void dispatch_sync_f(void *queue, void *context, void (*function)(void *)) {
    (void)queue;
    if (function) function(context);
}

/* ── Additional CF stubs ────────────────────────────────────────
 * These are needed by starship (Rust shell-prompt tool). */

/* CFBooleanGetTypeID — return a unique type ID for CFBoolean. */
unsigned long CFBooleanGetTypeID(void) {
    return 0x426f6f6c;  /* 'Bool' */
}

/* CFBooleanGetValue — return the boolean value (always false). */
int CFBooleanGetValue(void *cf) {
    (void)cf;
    return 0;
}

/* CFStringCreateWithBytes is defined in misc/misc.c (for Go binaries).
 * We override it here with a better implementation that returns an sc_obj
 * so CFStringGetBytes/CFStringGetCStringPtr work correctly. The __asm__
 * alias ensures our version takes precedence at the symbol level. */
extern void *macify_CFStringCreateWithBytes(void *alloc, const void *bytes,
                                             long numBytes, unsigned long encoding,
                                             unsigned char isExternal) __asm__("CFStringCreateWithBytes");
void *macify_CFStringCreateWithBytes(void *alloc, const void *bytes,
                                     long numBytes, unsigned long encoding,
                                     unsigned char isExternal) {
    (void)alloc; (void)encoding; (void)isExternal;
    if (!bytes && numBytes > 0) return NULL;
    /* Allocate sc_obj + copy of bytes + null terminator */
    struct sc_obj *s = (struct sc_obj *)calloc(1, sizeof(struct sc_obj));
    if (!s) return NULL;
    s->tag = SC_TAG_STRING;
    s->count = (uint32_t)numBytes;
    if (numBytes > 0) {
        char *copy = (char *)malloc(numBytes + 1);
        if (!copy) { free(s); return NULL; }
        memcpy(copy, bytes, numBytes);
        copy[numBytes] = '\0';
        s->data = copy;
    } else {
        s->data = strdup("");
    }
    return s;
}

/* CFBooleanCreate — create a CFBoolean. Return a sentinel. */
static char cf_bool_true_sentinel[16] = {1};
static char cf_bool_false_sentinel[16] = {0};
void *CFBooleanCreate(void *alloc, int value) {
    (void)alloc;
    return value ? cf_bool_true_sentinel : cf_bool_false_sentinel;
}

/* kCFBooleanTrue / kCFBooleanFalse — global CFBoolean refs. */
void *kCFBooleanTrue = cf_bool_true_sentinel;
void *kCFBooleanFalse = cf_bool_false_sentinel;

/* ── LaunchServices stub ────────────────────────────────────────
 * LSCopyApplicationURLsForBundleIdentifier — return NULL (no apps found). */
void *LSCopyApplicationURLsForBundleIdentifier(void *bundleID, void *error) {
    (void)bundleID;
    if (error) *(void **)error = NULL;
    return NULL;  /* empty CFArray */
}

/* LSOpenURLs — return 0 (failed). */
int LSOpenURLs(void *urls, void *role, void *flags, void *params, void *outURLs) {
    (void)urls; (void)role; (void)flags; (void)params; (void)outURLs;
    return 0;
}

/* ── IOMasterPort ───────────────────────────────────────────────
 * IOMasterPort is a function that returns the IOKit master port.
 * We return 0 (the default port = kIOMasterPortDefault). */
int IOMasterPort(void *unused, void **port) {
    (void)unused;
    if (port) *port = (void *)0;
    return 0;  /* kIOReturnSuccess */
}

/* ── NSDefaultRunLoopMode / NSUserNotificationDefaultSoundName ─
 * These are global NSString/CFString constants. We provide NULL. */
void *NSDefaultRunLoopMode = NULL;
void *NSUserNotificationDefaultSoundName = NULL;

/* Additional common NSString constants used by Foundation/AppKit. */
void *NSLocalizedString = NULL;
void *NSBundleDidLoadNotification = NULL;
void *NSDidBecomeActiveNotification = NULL;
void *NSWillBecomeInactiveNotification = NULL;
