/* Split from misc.c */
#include "../shim.h"

/* misc.c — remaining macOS compatibility stubs */
#include "../shim.h"
#include <sys/mount.h>
#include <ucontext.h>
#include <stdarg.h>
#include <malloc.h>

/* ── libgcc_s loading for _Unwind_* functions ────────────────── */

static void *libgcc_s_handle = NULL;

static void __attribute__((unused)) ensure_libgcc(void) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (!libgcc_s_handle)
            libgcc_s_handle = dlopen("libgcc_s.so.2", RTLD_NOW | RTLD_GLOBAL);
    }
}

/* dyld_stub_binder — macOS lazy binding handler. Mac-ify resolves all lazy
 * binds eagerly at load time, so this should never be called. If it is, a
 * lazy symbol wasn't resolved — return 0 (NULL/no-op) so the binary can
 * continue running instead of crashing. This is safer than abort(). */

void dyld_stub_binder(void) {
    /* Return 0 — the calling stub expects a function address.
     * The binary will get a NULL function pointer and likely crash
     * when it tries to call it, but at least we get further. */
    if (getenv("MACIFY_VERBOSE"))
        fprintf(stderr, "macify: dyld_stub_binder called — unresolved lazy symbol\n");
    __asm__ volatile("xor %rax, %rax; ret");
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

__attribute__((noinline))
void ___chkstk_darwin(unsigned long size) {
    (void)size;
    /* No-op on Linux — the kernel handles stack growth automatically. */
    __asm__ volatile("" ::: "memory");
}

/* Also provide __chkstk_darwin (two underscores) for completeness */
__attribute__((noinline))
void __chkstk_darwin(unsigned long size) {
    (void)size;
    __asm__ volatile("" ::: "memory");
}

/* ── Math functions (macOS-specific) ─────────────────────────── */

#include <math.h>

/* These are macOS-specific math functions. They must be exported so
 * that resolve_symbol() can find them when a dylib imports them.
 * Use __asm__ labels to export with macOS-style names. */

double macify___exp10(double x) __asm__("__exp10");
double macify___exp10(double x) { return exp10(x); }

typedef struct { double sin_val, cos_val; } macos_double2;
macos_double2 macify___sincos_stret(double x) __asm__("__sincos_stret");
macos_double2 macify___sincos_stret(double x) {
    macos_double2 r = { sin(x), cos(x) };
    return r;
}
macos_double2 macify___sincospi_stret(double x) __asm__("__sincospi_stret");
macos_double2 macify___sincospi_stret(double x) {
    macos_double2 r = { sin(x * M_PI), cos(x * M_PI) };
    return r;
}

/* 128-bit integer math — libgcc_s provides these, but we provide
 * fallbacks with weak symbols so they don't override libgcc_s. */
__attribute__((weak)) __int128 __modti3(__int128 a, __int128 b) { return a % b; }
__attribute__((weak)) unsigned __int128 __umodti3(unsigned __int128 a, unsigned __int128 b) { return a % b; }
__attribute__((weak)) __int128 __divti3(__int128 a, __int128 b) { return a / b; }
__attribute__((weak)) unsigned __int128 __udivti3(unsigned __int128 a, unsigned __int128 b) { return a / b; }

/* ── Mach kernel stubs ───────────────────────────────────────── */

const char *macify_mach_error_string(int err) __asm__("mach_error_string");
const char *macify_mach_error_string(int err) { (void)err; return "unknown mach error"; }

int macify_mach_wait_until(unsigned long when) __asm__("mach_wait_until");
int macify_mach_wait_until(unsigned long when) { (void)when; return 0; }

int macify_task_set_exception_ports(int t, int f, void *h, int b, int fc) __asm__("task_set_exception_ports");
int macify_task_set_exception_ports(int t, int f, void *h, int b, int fc) {
    (void)t;(void)f;(void)h;(void)b;(void)fc; return 0;
}

int macify_task_swap_exception_ports(int t, int f, void *oh, int b, int fc, void *nh, int *ob, int *of) __asm__("task_swap_exception_ports");
int macify_task_swap_exception_ports(int t, int f, void *oh, int b, int fc, void *nh, int *ob, int *of) {
    (void)t;(void)f;(void)oh;(void)b;(void)fc;
    if (nh) *(void**)nh = NULL;
    if (ob) *ob = 0;
    if (of) *of = 0;
    return 0;
}

int macify_vm_region_recurse_64(int t, int *fl, void *i, int *c, unsigned long *a) __asm__("vm_region_recurse_64");
int macify_vm_region_recurse_64(int t, int *fl, void *i, int *c, unsigned long *a) {
    (void)t;(void)fl;(void)i;(void)c;(void)a; return 1;
}

/* ── Filesystem attribute list stubs ─────────────────────────── */

int macify_getattrlist(const char *p, void *a, void *b, size_t s, unsigned long o) __asm__("getattrlist");
int macify_getattrlist(const char *p, void *a, void *b, size_t s, unsigned long o) {
    (void)p;(void)a;(void)b;(void)s;(void)o; errno = ENOTSUP; return -1;
}

int macify_fgetattrlist(int fd, void *a, void *b, size_t s, unsigned long o) __asm__("fgetattrlist");
int macify_fgetattrlist(int fd, void *a, void *b, size_t s, unsigned long o) {
    (void)fd;(void)a;(void)b;(void)s;(void)o; errno = ENOTSUP; return -1;
}

int macify_setattrlist(const char *p, void *a, void *b, size_t s, unsigned long o) __asm__("setattrlist");
int macify_setattrlist(const char *p, void *a, void *b, size_t s, unsigned long o) {
    (void)p;(void)a;(void)b;(void)s;(void)o; errno = ENOTSUP; return -1;
}

int macify_fsetattrlist(int fd, void *a, void *b, size_t s, unsigned long o) __asm__("fsetattrlist");
int macify_fsetattrlist(int fd, void *a, void *b, size_t s, unsigned long o) {
    (void)fd;(void)a;(void)b;(void)s;(void)o; errno = ENOTSUP; return -1;
}

/* ── System stubs ────────────────────────────────────────────── */

extern void *macify_image_header;
void *macify__NSGetMachExecuteHeader(void) __asm__("_NSGetMachExecuteHeader");
void *macify__NSGetMachExecuteHeader(void) { return macify_image_header; }

int macify_getpeereid(int fd, uid_t *euid, gid_t *egid) __asm__("getpeereid");
int macify_getpeereid(int fd, uid_t *euid, gid_t *egid) {
    (void)fd; if (euid) *euid = getuid(); if (egid) *egid = getgid(); return 0;
}

int macify_setrgid(gid_t gid) __asm__("setrgid");
int macify_setrgid(gid_t gid) { return setregid(gid, -1); }

int macify_setruid(uid_t uid) __asm__("setruid");
int macify_setruid(uid_t uid) { return setreuid(uid, -1); }

__attribute__((weak))
char *macify_crypt(const char *key, const char *salt) __asm__("crypt");
char *macify_crypt(const char *key, const char *salt) {
    (void)key; static char d[3] = "x\0";
    if (salt && salt[0]) { d[0] = salt[0]; d[1] = salt[1] ? salt[1] : '\0'; }
    d[2] = '\0'; return d;
}

/* ── CoreFoundation stubs ────────────────────────────────────── */

void *macify_CFStringCreateMutableCopy(void *a, long m, void *s) __asm__("CFStringCreateMutableCopy");
void *macify_CFStringCreateMutableCopy(void *a, long m, void *s) { (void)a;(void)m;(void)s; return NULL; }

void macify_CFStringNormalize(void *s, int f) __asm__("CFStringNormalize");
void macify_CFStringNormalize(void *s, int f) { (void)s;(void)f; }

/* ── Unwind stubs ────────────────────────────────────────────── */

typedef ucontext_t unw_context_t;
typedef void unw_cursor_t;

int macify_unw_getcontext(unw_context_t *cp) __asm__("unw_getcontext");
int macify_unw_getcontext(unw_context_t *cp) { (void)cp; return 0; }

int macify_unw_init_local(unw_cursor_t *c, unw_context_t *cp) __asm__("unw_init_local");
int macify_unw_init_local(unw_cursor_t *c, unw_context_t *cp) { (void)c;(void)cp; return -1; }

int macify_unw_step(unw_cursor_t *c) __asm__("unw_step");
int macify_unw_step(unw_cursor_t *c) { (void)c; return 0; }

int macify_unw_get_reg(unw_cursor_t *c, int r, unsigned long *v) __asm__("unw_get_reg");
int macify_unw_get_reg(unw_cursor_t *c, int r, unsigned long *v) { (void)c;(void)r; if (v) *v = 0; return -1; }

int macify_unw_set_reg(unw_cursor_t *c, int r, unsigned long v) __asm__("unw_set_reg");
int macify_unw_set_reg(unw_cursor_t *c, int r, unsigned long v) { (void)c;(void)r;(void)v; return -1; }

int macify_unw_get_proc_name(unw_cursor_t *c, char *b, size_t l, unsigned long *o) __asm__("unw_get_proc_name");
int macify_unw_get_proc_name(unw_cursor_t *c, char *b, size_t l, unsigned long *o) {
    (void)c; if (b && l > 0) b[0] = '\0'; if (o) *o = 0; return -1;
}

/* ── os_log / os_signpost stubs ──────────────────────────────── */

/* macOS unified logging (os_log) — return dummy log objects.
 * os_log_create returns a non-NULL opaque pointer; we use a static. */
static char macify_dummy_log_obj[32];
void *macify_os_log_create(const char *subsystem, const char *category) __asm__("os_log_create");
void *macify_os_log_create(const char *subsystem, const char *category) {
    (void)subsystem; (void)category; return macify_dummy_log_obj;
}

int macify_os_log_type_enabled(void *log, int type) __asm__("os_log_type_enabled");
int macify_os_log_type_enabled(void *log, int type) { (void)log; (void)type; return 0; }

int macify_os_signpost_enabled(void *log) __asm__("os_signpost_enabled");
int macify_os_signpost_enabled(void *log) { (void)log; return 0; }

void macify_os_signpost_emit_with_name_impl(void *log, int type, const char *name, ...) __asm__("_os_signpost_emit_with_name_impl");
void macify_os_signpost_emit_with_name_impl(void *log, int type, const char *name, ...) {
    (void)log; (void)type; (void)name;
}

/* ── Mach VM stubs ───────────────────────────────────────────── */

/* mach_make_memory_entry_64 — returns a send right (mach port).
 * Return MACH_PORT_NULL (0) to indicate failure. */
unsigned int macify_mach_make_memory_entry_64(int target, unsigned long *size,
    unsigned long offset, int permission, int *entry_handle, int parent_entry)
    __asm__("mach_make_memory_entry_64");
unsigned int macify_mach_make_memory_entry_64(int target, unsigned long *size,
    unsigned long offset, int permission, int *entry_handle, int parent_entry) {
    (void)target; (void)size; (void)offset; (void)permission;
    (void)entry_handle; (void)parent_entry; return 0;
}

/* mach_vm_map — maps memory at a specific address.
 * Returns KERN_SUCCESS (0) on success, KERN_FAILURE (1) on failure. */
int macify_mach_vm_map(int target, unsigned long *address, unsigned long size,
    unsigned long mask, int flags, int object, unsigned long offset,
    int copy, int cur_protection, int max_protection)
    __asm__("mach_vm_map");
int macify_mach_vm_map(int target, unsigned long *address, unsigned long size,
    unsigned long mask, int flags, int object, unsigned long offset,
    int copy, int cur_protection, int max_protection) {
    (void)target; (void)mask; (void)flags; (void)object;
    (void)offset; (void)copy; (void)cur_protection; (void)max_protection;
    /* Fall back to mmap */
    void *p = mmap((void*)(address ? *address : 0), size,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    if (address) *address = (unsigned long)p;
    return 0;
}

/* mach_vm_remap — remaps memory from one address to another. */
int macify_mach_vm_remap(int target, unsigned long *dst, unsigned long size,
    unsigned long mask, int flags, int src_task, unsigned long src,
    int copy, int *cur_protection, int *max_protection)
    __asm__("mach_vm_remap");
int macify_mach_vm_remap(int target, unsigned long *dst, unsigned long size,
    unsigned long mask, int flags, int src_task, unsigned long src,
    int copy, int *cur_protection, int *max_protection) {
    (void)target; (void)mask; (void)flags; (void)src_task;
    (void)src; (void)copy;
    /* Fall back to memcpy via mmap */
    void *p = mmap((void*)(dst ? *dst : 0), size,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    memcpy(p, (void*)src, size);
    if (dst) *dst = (unsigned long)p;
    if (cur_protection) *cur_protection = PROT_READ | PROT_WRITE;
    if (max_protection) *max_protection = PROT_READ | PROT_WRITE;
    return 0;
}

/* ── Thread/QoS stubs ────────────────────────────────────────── */

/* pthread_mach_thread_np — returns the mach thread port for a pthread.
 * On Linux, we return the tid as a stand-in. */
unsigned int macify_pthread_mach_thread_np(void *thread) __asm__("pthread_mach_thread_np");
unsigned int macify_pthread_mach_thread_np(void *thread) {
    (void)thread; return (unsigned int)syscall(186); /* SYS_gettid */
}

int macify_pthread_set_qos_class_self_np(int qos, int relpri) __asm__("pthread_set_qos_class_self_np");
int macify_pthread_set_qos_class_self_np(int qos, int relpri) {
    (void)qos; (void)relpri; return 0;
}

/* ── sys_icache stub ─────────────────────────────────────────── */

/* sys_icache_invalidate — flush instruction cache.
 * On x86_64, the instruction cache is coherent, so this is a no-op. */
void macify_sys_icache_invalidate(void *addr, size_t size) __asm__("sys_icache_invalidate");
void macify_sys_icache_invalidate(void *addr, size_t size) { (void)addr; (void)size; }

/* ── getsectiondata stub ─────────────────────────────────────── */

/* getsectiondata — returns pointer to section data in a loaded image.
 * Returns NULL if section not found. We can't easily implement this
 * without tracking all loaded images, so return NULL. */
void *macify_getsectiondata(void *mhdr, const char *segname, const char *sectname, unsigned long *size)
    __asm__("getsectiondata");
void *macify_getsectiondata(void *mhdr, const char *segname, const char *sectname, unsigned long *size) {
    (void)mhdr; (void)segname; (void)sectname;
    if (size) *size = 0;
    return NULL;
}

/* ── __floattidf stub (compiler-rt soft-float for __int128 → double) ── */

double macify___floattidf(__int128 x) __asm__("__floattidf");
double macify___floattidf(__int128 x) {
    /* Convert __int128 to double via signed long long (lossy but safe) */
    return (double)(long long)x;
}

/* ── Network stubs (macOS-specific sendmsg_x/recvmsg_x) ──────── */

/* recvmsg_x / sendmsg_x — macOS batch send/recv syscalls.
 * Not available on Linux; return -1 with ENOSYS. */
long macify_recvmsg_x(int fd, void *msg, unsigned int cnt, int flags) __asm__("recvmsg_x");
long macify_recvmsg_x(int fd, void *msg, unsigned int cnt, int flags) {
    (void)fd; (void)msg; (void)cnt; (void)flags; errno = ENOSYS; return -1;
}

long macify_sendmsg_x(int fd, void *msg, unsigned int cnt, int flags) __asm__("sendmsg_x");
long macify_sendmsg_x(int fd, void *msg, unsigned int cnt, int flags) {
    (void)fd; (void)msg; (void)cnt; (void)flags; errno = ENOSYS; return -1;
}

/* ── CoreFoundation stubs (additional) ───────────────────────── */

/* CFArraySetValueAtIndex — sets a value in a CFArray. We don't have CFArray,
 * so this is a no-op. */
void macify_CFArraySetValueAtIndex(void *array, long idx, void *value) __asm__("CFArraySetValueAtIndex");
void macify_CFArraySetValueAtIndex(void *array, long idx, void *value) {
    (void)array; (void)idx; (void)value;
}

int macify_CFDictionaryContainsKey(void *dict, const void *key) __asm__("CFDictionaryContainsKey");
int macify_CFDictionaryContainsKey(void *dict, const void *key) {
    (void)dict; (void)key; return 0;
}

void *macify_CFDictionaryCreate(void *alloc, const void **keys, const void **values,
    long count, const void *cb) __asm__("CFDictionaryCreate");
void *macify_CFDictionaryCreate(void *alloc, const void **keys, const void **values,
    long count, const void *cb) {
    (void)alloc; (void)keys; (void)values; (void)count; (void)cb;
    return NULL; /* caller should check for NULL */
}

void *macify_CFTimeZoneCopyDefault(void) __asm__("CFTimeZoneCopyDefault");
void *macify_CFTimeZoneCopyDefault(void) { return NULL; }

/* CFType dictionary key/value callbacks — return as NULL (caller should check) */
static char macify_cf_callbacks[64];
const void *macify_kCFTypeDictionaryKeyCallBacks_ptr __asm__("kCFTypeDictionaryKeyCallBacks") = macify_cf_callbacks;
const void *macify_kCFTypeDictionaryValueCallBacks_ptr __asm__("kCFTypeDictionaryValueCallBacks") = macify_cf_callbacks;

/* ── Security framework stubs ────────────────────────────────── */

/* SecItemCopyMatching — searches the keychain. Returns errSecItemNotFound. */
int macify_SecItemCopyMatching(void *query, void *result) __asm__("SecItemCopyMatching");
int macify_SecItemCopyMatching(void *query, void *result) {
    (void)query; (void)result; return -25300; /* errSecItemNotFound */
}

void *macify_SecPolicyCopyProperties(void *policy) __asm__("SecPolicyCopyProperties");
void *macify_SecPolicyCopyProperties(void *policy) { (void)policy; return NULL; }

int macify_SecTrustSettingsCopyTrustSettings(void *cert, int domain, void **settings) __asm__("SecTrustSettingsCopyTrustSettings");
int macify_SecTrustSettingsCopyTrustSettings(void *cert, int domain, void **settings) {
    (void)cert; (void)domain; if (settings) *settings = NULL; return -25300;
}

/* Security framework constants — return as NULL (they're CFStrings on macOS) */
static char macify_sec_dummy[16];
const void *macify_kSecClass_ptr __asm__("kSecClass") = macify_sec_dummy;
const void *macify_kSecClassCertificate_ptr __asm__("kSecClassCertificate") = macify_sec_dummy;
const void *macify_kSecMatchLimit_ptr __asm__("kSecMatchLimit") = macify_sec_dummy;
const void *macify_kSecMatchLimitAll_ptr __asm__("kSecMatchLimitAll") = macify_sec_dummy;
const void *macify_kSecPolicyAppleSSL_ptr __asm__("kSecPolicyAppleSSL") = macify_sec_dummy;
const void *macify_kSecPolicyOid_ptr __asm__("kSecPolicyOid") = macify_sec_dummy;
const void *macify_kSecReturnRef_ptr __asm__("kSecReturnRef") = macify_sec_dummy;

