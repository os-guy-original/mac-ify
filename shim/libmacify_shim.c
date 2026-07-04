/*
 * libmacify_shim.c — Mac-ify libSystem shim
 *
 * Provides macOS-specific C library functions that glibc does not provide
 * or implements differently. The loader dlopens this library first when
 * resolving symbols; if a symbol isn't found here, it falls back to libc.so.6.
 *
 * Key functions:
 *   __errno()          — macOS returns int* to thread-local errno
 *   _NSGetEnviron()    — returns &environ
 *   ___progname        — program name global
 *   __stack_chk_fail() — stack canary failure handler
 *   _dyld_image_count() and friends — dynamic loader introspection
 *   mach_* traps       — stubs that return appropriate errors
 *
 * Build: see Makefile
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/stat.h>
#include <spawn.h>
#include <time.h>
#include <dirent.h>

/* __errno() — macOS returns a pointer to the thread-local errno.
 * 
 * On macOS, libc's __errno() returns `int *` (pointer to per-thread
 * errno). On Linux, glibc uses __errno_location() which returns `int *`
 * to the same thing. We bridge them.
 * 
 * Many macOS binaries call __errno() directly (not through a GOT entry)
 * to get the errno pointer, then read *ptr after a failed syscall.
 */


/* macOS convention: __errno (with one underscore, as called by C code) */
int *__errno(void) {
    return __errno_location();
}

/* Also provide _errno as some code calls it directly */
int *_errno(void) {
    return __errno_location();
}

/* _NSGetEnviron — returns pointer to the environ global.
 * 
 * macOS binaries access environment via _NSGetEnviron() which returns
 * char ***. On Linux, environ is a direct global.
 */

extern char **environ;

char ***_NSGetEnviron(void) {
    return &environ;
}

/* ___progname — program name global.
 * 
 * macOS has a global ___progname (three underscores) that holds the
 * program name. Many macOS binaries reference it.
 */

char *___progname = "macify-app";

/* __progname (two underscores) is also common */
char *__progname = "macify-app";

/* __stack_chk_guard — stack canary value global.
 * 
 * On macOS, __stack_chk_guard is a global variable (not function)
 * that holds the stack canary value. GCC/clang code reads this
 * variable and puts its value on the stack at function entry, then
 * checks it at function exit.
 * 
 * On Linux x86_64, glibc uses %fs:0x28 (TLS) for the canary instead
 * of a global variable. But macOS binaries reference __stack_chk_guard
 * as a regular symbol, so we need to provide it.
 * 
 * We initialize it with a random-ish value and also sync it from
 * glibc's TLS canary at startup.
 */

/* Initialize with a non-zero canary value. The exact value doesn't
 * matter much for functionality — it just needs to be consistent
 * between function entry and exit. */
uintptr_t __stack_chk_guard = 0x1234567890ABCDEFu;

/* Also provide _STACK_CHK_GUARD (some macOS code references this variant) */
uintptr_t _STACK_CHK_GUARD = 0x1234567890ABCDEFu;

void __stack_chk_fail(void) {
    fprintf(stderr, "macify: stack smashing detected\n");
    abort();
}

/* _dyld_image_count / _dyld_get_image_* — dynamic loader introspection.
 * 
 * macOS apps can query the dynamic loader for loaded images. We provide
 * minimal stubs that report just the main executable.
 */

static const char *__macify_image_name = "/macify/app.bin";

uint32_t _dyld_image_count(void) {
    return 1;  /* just the main executable */
}

const char *_dyld_get_image_name(uint32_t image_index) {
    if (image_index == 0) return __macify_image_name;
    return NULL;
}

/* The actual load base of the main image, set by the loader.
 * _dyld_get_image_header(0) must return this (the slid address). */
static uint64_t macify_image_header = 0;

void __macify_set_image_header(uint64_t header) {
    macify_image_header = header;
}

uint64_t _dyld_get_image_header(uint64_t image_index) {
    if (image_index == 0) return macify_image_header;
    return 0;
}

int64_t _dyld_get_image_vmaddr_slide(uint64_t image_index) {
    /* Return the slide. The loader sets macify_image_header. */
    (void)image_index;
    return 0;  /* slide is already included in macify_image_header */
}

uint64_t _dyld_get_image_slide(uint64_t image_index) {
    return _dyld_get_image_vmaddr_slide(image_index);
}

/* mach_* — Mach trap stubs.
 * 
 * macOS binaries may call mach traps directly. We stub the common ones
 * to return appropriate values. Most are no-ops or return errors.
 */

/* mach_msg is the core Mach IPC primitive. Stub it to fail. */
int mach_msg(void *msg, int option, uint32_t send_size,
             uint32_t rcv_size, int rcv_name, int timeout, int notify) {
    (void)msg; (void)option; (void)send_size; (void)rcv_size;
    (void)rcv_name; (void)timeout; (void)notify;
    return 0x10000003;  /* MACH_SEND_INVALID_DEST-ish */
}

/* mach_port_t mach_task_self() — returns the task port. Stub. */
uint32_t mach_task_self(void) {
    return 0x1000;  /* arbitrary nonzero */
}

uint32_t mach_thread_self(void) {
    return 0x2000;
}

/* mach_host_self */
uint32_t mach_host_self(void) {
    return 0x3000;
}

/* _pthread_* — macOS pthread variants.
 * 
 * macOS has some pthread functions with leading underscores that differ
 * slightly from POSIX. Most map directly to glibc equivalents.
 */

/* _pthread_getname_np — get thread name */
int _pthread_getname_np(pthread_t thread, char *name, size_t len) {
    return pthread_getname_np(thread, name, len);
}

/* __memset_chk / __memcpy_chk / __memmove_chk — fortified memory functions.
 * 
 * macOS uses these _chk variants for FORTIFY_SOURCE. glibc has them too,
 * but we provide them explicitly in case the macOS binary references them
 * with the leading underscore.
 */

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

/* _objc_* — Objective-C runtime stubs.
 * 
 * Many macOS binaries link against libobjc. We stub the common
 * functions. A real ObjC runtime would be needed for ObjC apps.
 */

/* objc_msgSend is the core ObjC message dispatch. Stub it. */
void *objc_msgSend(void *self, void *sel, ...) {
    (void)self; (void)sel;
    return NULL;
}

void objc_msgSendSuper(void) { }
void objc_msgSend_stret(void *stret, void *self, void *sel, ...) {
    (void)stret; (void)self; (void)sel;
}

/* Class lookup stubs */
void *objc_getClass(const char *name) {
    (void)name;
    return NULL;
}

void *objc_getMetaClass(const char *name) {
    (void)name;
    return NULL;
}

void *objc_allocateClassPair(void *superclass, const char *name, size_t extraBytes) {
    (void)superclass; (void)name; (void)extraBytes;
    return NULL;
}

void objc_registerClassPair(void *cls) {
    (void)cls;
}

/* sel_registerName — register a selector. Return the string as the "selector". */
void *sel_registerName(const char *name) {
    return (void *)name;
}

void *sel_getUid(const char *name) {
    return (void *)name;
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

/* __error — macOS alias for __errno. */

int *__error(void) {
    return __errno_location();
}

/* ___stderrp / ___stdinp / ___stdoutp — macOS FILE pointers.
 * 
 * On macOS, stdin/stdout/stderr are accessed via these global
 * FILE* pointers. On Linux, they're `stdin`/`stdout`/`stderr`.
 * We provide the macOS-named globals pointing to the same FILEs.
 */

#include <stdio.h>

/* These are the actual FILE* values. The macOS binary reads these
 * pointers to get stdin/stdout/stderr. */


/* Provide the macOS-named globals. The binary has ___stdinp (3 underscores),
 * which after stripping 1 becomes __stdinp (2 underscores). So we define
 * C globals with 2 underscores, which export as __stdinp on Linux. */
FILE *__stderrp = NULL;
FILE *__stdinp = NULL;
FILE *__stdoutp = NULL;

/* Constructor to initialize the stdio pointers */
__attribute__((constructor))
static void macify_init_stdio(void) {
    __stderrp = stderr;
    __stdinp = stdin;
    __stdoutp = stdout;

    /* Install our crash handler via raw syscall. We use a simple
     * sa_handler (not sa_sigaction) to avoid struct layout issues.
     * Syscall 13 = rt_sigaction on x86_64 Linux. */
    extern void macify_crash_proxy(int);
    struct {
        void (*handler)(int);
        unsigned long flags;
        unsigned long mask;
    } sa = { macify_crash_proxy, 0x40000000 /* SA_NODEFER */, 0 };
    syscall(13, 11, &sa, NULL, 8);  /* SIGSEGV */
    syscall(13, 7,  &sa, NULL, 8);  /* SIGBUS */
    syscall(13, 6,  &sa, NULL, 8);  /* SIGABRT */
}

/* Minimal crash handler — uses only write() to avoid stdio issues. */
void macify_crash_proxy(int sig) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "\n*** macify crash: signal %d ***\n", sig);
    write(2, buf, n);
    _exit(128 + sig);
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
static uint32_t macify_runetype[256];
static int16_t macify_maplower[256];
static int16_t macify_mapupper[256];

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

/* _tlv_atexit — TLV cleanup at exit.
 * 
 * Registers a cleanup function for TLV descriptors. Called when a
 * thread exits or the process exits. We use pthread cleanup.
 */

void _tlv_atexit(void (*fn)(void *), void *arg) {
    /* Register with atexit — simplified, doesn't perfectly match macOS semantics */
    /* For now, just call the function immediately on exit via atexit */
    (void)fn; (void)arg;
    /* No-op for now — TLV cleanup is not critical for most apps */
}

/* Mach time functions. */


unsigned long long mach_absolute_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

typedef struct {
    uint32_t numer;
    uint32_t denom;
} mach_timebase_info_data_t;

int mach_timebase_info(mach_timebase_info_data_t *info) {
    /* On Linux, CLOCK_MONOTONIC is already in nanoseconds */
    if (info) {
        info->numer = 1;
        info->denom = 1;
    }
    return 0;
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

/* macOS pthread extensions. */

/* The loader allocates an 8MB stack for the macOS binary and switches to
 * it before calling main(). But glibc's pthread_getattr_np for the main
 * thread still returns the KERNEL's stack info (from /proc/self/maps),
 * not our allocated stack. Rust's runtime uses pthread_get_stackaddr_np
 * to find the main thread's stack, computes guard page addresses from it,
 * and crashes when those don't match the actual stack pointer.
 *
 * Fix: the loader calls __macify_set_stack_info() with our allocated
 * stack base/size. pthread_get_stack*_np returns these values for the
 * main thread instead of querying glibc. */
static void *macify_main_stack_base = NULL;
static size_t macify_main_stack_size = 0;

void __macify_set_stack_info(void *base, size_t size) {
    macify_main_stack_base = base;
    macify_main_stack_size = size;
}

void *pthread_get_stackaddr_np(pthread_t thread) {
    /* For the main thread, return our allocated stack top. For other
     * threads, query glibc. We detect the main thread by checking if
     * thread == pthread_self() AND our stack info has been set. */
    if (macify_main_stack_base && thread == pthread_self()) {
        return (char *)macify_main_stack_base + macify_main_stack_size;
    }
    pthread_attr_t attr;
    void *stackaddr = NULL;
    size_t stacksize = 0;
    pthread_getattr_np(thread, &attr);
    pthread_attr_getstack(&attr, &stackaddr, &stacksize);
    pthread_attr_destroy(&attr);
    return (char *)stackaddr + stacksize;  /* top of stack */
}

size_t pthread_get_stacksize_np(pthread_t thread) {
    if (macify_main_stack_base && thread == pthread_self()) {
        return macify_main_stack_size;
    }
    pthread_attr_t attr;
    size_t stacksize = 0;
    pthread_getattr_np(thread, &attr);
    pthread_attr_getstacksize(&attr, &stacksize);
    pthread_attr_destroy(&attr);
    return stacksize;
}

/* TLV (Thread-Local Variable) implementation.
 *
 * macOS TLV uses three sections: __thread_vars (array of tlv_descriptor),
 * __thread_data (initial values), __thread_bss (zero-init, size only).
 * Each descriptor holds a thunk (initially tlv_bootstrap), a key, and an
 * offset into the per-thread block. Code accesses a TLV by calling
 * desc->thunk(desc), which returns a pointer to the variable's storage.
 * The loader registers section info via __macify_set_tlv_info() before main().
 */

struct tlv_descriptor {
    void *(*thunk)(struct tlv_descriptor *);
    void *key;
    unsigned long offset;
};

/* TLV section info, set by the loader */
static void *tlv_data_base = NULL;       /* __thread_data section addr (slid) */
static size_t tlv_data_size = 0;         /* __thread_data section size */
static size_t tlv_bss_size = 0;          /* __thread_bss section size */
/* Total per-thread block = tlv_data_size + tlv_bss_size */

/* Per-thread TLV block */
static pthread_key_t tlv_block_key;
static pthread_once_t tlv_block_once = PTHREAD_ONCE_INIT;

static void tlv_block_destructor(void *arg) {
    free(arg);
}

static void tlv_block_init(void) {
    pthread_key_create(&tlv_block_key, tlv_block_destructor);
}

/* Called by the loader to set TLV section info */
void __macify_set_tlv_info(void *data_base, size_t data_size, size_t bss_size) {
    tlv_data_base = data_base;
    tlv_data_size = data_size;
    tlv_bss_size = bss_size;
}

/* Get or create the per-thread TLV block */
static void *get_tlv_block(void) {
    pthread_once(&tlv_block_once, tlv_block_init);

    void *block = pthread_getspecific(tlv_block_key);
    if (!block) {
        size_t total = tlv_data_size + tlv_bss_size;
        if (total == 0) total = 4096;  /* fallback */
        block = calloc(1, total);
        /* Initialize: copy __thread_data initial values */
        if (tlv_data_base && tlv_data_size > 0) {
            memcpy(block, tlv_data_base, tlv_data_size);
        }
        /* __thread_bss is already zeroed by calloc */
        pthread_setspecific(tlv_block_key, block);
    }
    return block;
}

/* C implementation of TLV bootstrap. Called from the assembly wrapper
 * which preserves caller-saved registers. Returns pointer to the
 * variable's per-thread storage. */
void *__tlv_bootstrap_impl(struct tlv_descriptor *desc) {
    void *block = get_tlv_block();
    return (char *)block + desc->offset;
}

/* macOS TLV thunk ABI requires preserving ALL registers except rax.
 * Rust's runtime (and possibly other code) relies on this — it loads
 * rcx/rdx/rsi before calling the thunk and uses them after, expecting
 * them to be unchanged. glibc's pthread_getspecific clobbers these,
 * so we wrap the C implementation in an assembly trampoline that
 * saves and restores all caller-saved registers.
 *
 * Stack layout after the 9 pushes (top to bottom):
 *   rsp+0x00: saved r11
 *   rsp+0x08: saved r10
 *   rsp+0x10: saved r9
 *   rsp+0x18: saved r8
 *   rsp+0x20: saved rdi   <- original desc argument
 *   rsp+0x28: saved rsi
 *   rsp+0x30: saved rdx
 *   rsp+0x38: saved rcx
 *   rsp+0x40: saved rax
 * Then the call to __tlv_bootstrap_impl pushes a return address at rsp-8.
 *
 * We pass desc (saved at rsp+0x20) as rdi to the C function.
 * After the call, we overwrite the saved rax slot with the return value,
 * then pop all 9 registers. The final pop rax restores the (now overwritten)
 * saved value, which is the return value.
 */
__attribute__((naked))
void *tlv_bootstrap(struct tlv_descriptor *desc) {
    __asm__ volatile (
        "push %rax\n\t"
        "push %rcx\n\t"
        "push %rdx\n\t"
        "push %rsi\n\t"
        "push %rdi\n\t"
        "push %r8\n\t"
        "push %r9\n\t"
        "push %r10\n\t"
        "push %r11\n\t"
        "movq 0x20(%rsp), %rdi\n\t"     /* rdi = original desc (saved at rsp+0x20) */
        "call __tlv_bootstrap_impl\n\t"
        "movq %rax, 0x40(%rsp)\n\t"     /* overwrite saved rax with return value */
        "pop %r11\n\t"
        "pop %r10\n\t"
        "pop %r9\n\t"
        "pop %r8\n\t"
        "pop %rdi\n\t"
        "pop %rsi\n\t"
        "pop %rdx\n\t"
        "pop %rcx\n\t"
        "pop %rax\n\t"                  /* restores return value (was overwritten) */
        "ret\n\t"
    );
}

/* _tlv_bootstrap and tlv_get_addr are aliases for tlv_bootstrap — they
 * all use the same assembly wrapper that preserves registers. */
void *_tlv_bootstrap(struct tlv_descriptor *desc) {
    return tlv_bootstrap(desc);
}

void *tlv_get_addr(struct tlv_descriptor *desc) {
    return tlv_bootstrap(desc);
}

/* __NSGetArgc / __NSGetArgv / __NSGetExecutablePath
 * 
 * macOS provides these functions to access argc, argv, and the
 * executable path. They return pointers to the actual data.
 */

static int __macify_argc = 0;
static char **__macify_argv = NULL;
static char __macify_exec_path[4096] = "/macify/app";

void __macify_set_args(int argc, char **argv, const char *exec_path) {
    __macify_argc = argc;
    __macify_argv = argv;
    if (exec_path) {
        strncpy(__macify_exec_path, exec_path, sizeof(__macify_exec_path) - 1);
    }
}

int *_NSGetArgc(void) {
    return &__macify_argc;
}

char ***_NSGetArgv(void) {
    return &__macify_argv;
}

int _NSGetExecutablePath(char *buf, uint32_t *bufsize) {
    if (!buf || !bufsize) return -1;
    size_t len = strlen(__macify_exec_path);
    if (*bufsize < len + 1) {
        *bufsize = len + 1;
        return -1;
    }
    memcpy(buf, __macify_exec_path, len + 1);
    *bufsize = len;
    return 0;
}

/* _Unwind_* — C++ exception unwinding functions.
 * 
 * These are from libunwind/libc++abi. macOS provides them in libSystem.
 * Linux provides them in libgcc_s.so. We forward to libgcc_s by
 * dlopen'ing it and dlsym'ing the real functions on first use.
 */

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


/* _dispatch_* — libdispatch stubs.
 * 
 * macOS uses Grand Central Dispatch (GCD) heavily. We stub the
 * common functions. A real libdispatch port would be needed for
 * apps that use GCD.
 */

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
 * calls atexit handlers before _exit(). Our shim must do the same. */
void exit(int status) {
    /* Call glibc's exit to flush stdio buffers and run atexit handlers.
     * We can't call exit() directly because we'd recurse. Use the
     * internal __exit symbol or just call _exit after fflush. */
    fflush(NULL);  /* Flush all stdio streams */
    _exit(status);
}


/* Self-contained pthread TLS implementation.
 * 
 * macOS and glibc have different pthread_key_t sizes and different
 * pthread_once_t layouts. Instead of trying to bridge these, we
 * provide our own simple TLS that works with macOS-sized keys.
 * 
 * We maintain our own key table (256 slots). pthread_key_create
 * allocates a slot. pthread_setspecific/getspecific use the slot.
 * The macOS binary stores keys in 8-byte variables; we mask to
 * our 0-255 range.
 */

#include <pthread.h>

#define MACIFY_MAX_KEYS 256
static void *macify_tls_keys[MACIFY_MAX_KEYS];
static int macify_next_key = 0;
static pthread_mutex_t macify_tls_mutex = PTHREAD_MUTEX_INITIALIZER;
static void (*macify_destructors[MACIFY_MAX_KEYS])(void *);

/* Our own pthread_key_create — allocates from our table */
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
    pthread_mutex_lock(&macify_tls_mutex);
    int k = macify_next_key++;
    pthread_mutex_unlock(&macify_tls_mutex);
    
    if (k >= MACIFY_MAX_KEYS) return EAGAIN;
    
    /* Write key as a small integer (fits in both 4 and 8 byte variables) */
    *key = (pthread_key_t)k;
    macify_destructors[k] = destructor;
    macify_tls_keys[k] = NULL;
    return 0;
}

/* Our own pthread_setspecific — uses our table */
int pthread_setspecific(pthread_key_t key, const void *value) {
    unsigned int k = (unsigned int)(unsigned long)key;
    if (k >= MACIFY_MAX_KEYS) {
        fprintf(stderr, "macify-shim: pthread_setspecific: key %u out of range\n", k);
        return EINVAL;
    }
    macify_tls_keys[k] = (void *)value;
    return 0;
}

/* Our own pthread_getspecific — uses our table */
void *pthread_getspecific(pthread_key_t key) {
    unsigned int k = (unsigned int)(unsigned long)key;
    if (k >= MACIFY_MAX_KEYS) return NULL;
    return macify_tls_keys[k];
}

/* Our own pthread_once — simpler than glibc's, works with any once_t size.
 *
 * macOS uses a magic value 0x30B1BCBA for PTHREAD_ONCE_INIT, NOT zero!
 * See macOS <pthread.h>: _PTHREAD_ONCE_SIG_init = 0x30B1BCBA
 * After init, macOS sets it to a different value. We just check if it
 * has been changed from the initial magic. */
#define MACOS_PTHREAD_ONCE_INIT 0x30B1BCBA

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    static pthread_mutex_t once_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&once_mutex);
    long val = *(long *)once_control;
    if (val == MACOS_PTHREAD_ONCE_INIT || val == 0) {
        /* Not yet initialized — call init */
        *(long *)once_control = 1;  /* Mark as done */
        pthread_mutex_unlock(&once_mutex);
        init_routine();
    } else {
        /* Already initialized */
        pthread_mutex_unlock(&once_mutex);
    }
    return 0;
}


/* macOS pthread synchronization objects have a completely different layout
 * from glibc's. Statically-initialized objects carry a macOS signature
 * (0x32AAABA7 for mutex, 0x3CB0B5BB for cond, 0x2DA8B3B4 for rwlock) in
 * their first 4 bytes. When glibc's pthread_mutex_lock sees this non-zero
 * value, it interprets it as "already locked" and deadlocks on a futex.
 *
 * Solution: override the pthread_mutex/cond/rwlock functions. On each call,
 * check if the object still has a macOS signature. If so, overwrite it
 * in-place with glibc's PTHREAD_*_INITIALIZER (macOS objects are 64+ bytes;
 * glibc's are 40 bytes, so the overwrite is safe). Then delegate to glibc's
 * real function via dlsym(RTLD_NEXT, ...).
 */

#define MACOS_PTHREAD_MUTEX_SIG  0x32AAABA7u
#define MACOS_PTHREAD_COND_SIG   0x3CB0B5BBu
#define MACOS_PTHREAD_RWLOCK_SIG 0x2DA8B3B4u

/* Cache glibc's real function pointers (resolved lazily on first use). */
static int   (*real_mutex_lock)(pthread_mutex_t *);
static int   (*real_mutex_trylock)(pthread_mutex_t *);
static int   (*real_mutex_unlock)(pthread_mutex_t *);
static int   (*real_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
static int   (*real_mutex_destroy)(pthread_mutex_t *);
static int   (*real_cond_wait)(pthread_cond_t *, pthread_mutex_t *);
static int   (*real_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
static int   (*real_cond_signal)(pthread_cond_t *);
static int   (*real_cond_broadcast)(pthread_cond_t *);
static int   (*real_cond_init)(pthread_cond_t *, const pthread_condattr_t *);
static int   (*real_cond_destroy)(pthread_cond_t *);
static int   (*real_rwlock_rdlock)(pthread_rwlock_t *);
static int   (*real_rwlock_wrlock)(pthread_rwlock_t *);
static int   (*real_rwlock_unlock)(pthread_rwlock_t *);
static int   (*real_rwlock_init)(pthread_rwlock_t *, const pthread_rwlockattr_t *);
static int   (*real_rwlock_destroy)(pthread_rwlock_t *);

static void init_real_pthread_funcs(void) {
    real_mutex_lock     = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    real_mutex_trylock  = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
    real_mutex_unlock   = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    real_mutex_init     = dlsym(RTLD_NEXT, "pthread_mutex_init");
    real_mutex_destroy  = dlsym(RTLD_NEXT, "pthread_mutex_destroy");
    real_cond_wait      = dlsym(RTLD_NEXT, "pthread_cond_wait");
    real_cond_timedwait = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
    real_cond_signal    = dlsym(RTLD_NEXT, "pthread_cond_signal");
    real_cond_broadcast = dlsym(RTLD_NEXT, "pthread_cond_broadcast");
    real_cond_init      = dlsym(RTLD_NEXT, "pthread_cond_init");
    real_cond_destroy   = dlsym(RTLD_NEXT, "pthread_cond_destroy");
    real_rwlock_rdlock  = dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");
    real_rwlock_wrlock  = dlsym(RTLD_NEXT, "pthread_rwlock_wrlock");
    real_rwlock_unlock  = dlsym(RTLD_NEXT, "pthread_rwlock_unlock");
    real_rwlock_init    = dlsym(RTLD_NEXT, "pthread_rwlock_init");
    real_rwlock_destroy = dlsym(RTLD_NEXT, "pthread_rwlock_destroy");
}

/* Convert a macOS-format mutex to glibc format in-place. The macOS mutex
 * is larger than glibc's (64+ vs 40 bytes), so overwriting the first
 * sizeof(pthread_mutex_t) bytes is safe. */
static void convert_macos_mutex(pthread_mutex_t *m) {
    unsigned int sig = *(unsigned int *)m;
    if (sig == MACOS_PTHREAD_MUTEX_SIG) {
        static const pthread_mutex_t glibc_init = PTHREAD_MUTEX_INITIALIZER;
        memcpy(m, &glibc_init, sizeof(pthread_mutex_t));
    }
}

static void convert_macos_cond(pthread_cond_t *c) {
    unsigned int sig = *(unsigned int *)c;
    if (sig == MACOS_PTHREAD_COND_SIG) {
        static const pthread_cond_t glibc_init = PTHREAD_COND_INITIALIZER;
        memcpy(c, &glibc_init, sizeof(pthread_cond_t));
    }
}

static void convert_macos_rwlock(pthread_rwlock_t *rw) {
    unsigned int sig = *(unsigned int *)rw;
    if (sig == MACOS_PTHREAD_RWLOCK_SIG) {
        static const pthread_rwlock_t glibc_init = PTHREAD_RWLOCK_INITIALIZER;
        memcpy(rw, &glibc_init, sizeof(pthread_rwlock_t));
    }
}

#define LAZY_INIT() do { \
    if (!real_mutex_lock) init_real_pthread_funcs(); \
} while (0)

int pthread_mutex_lock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    return real_mutex_lock(m);
}

int pthread_mutex_trylock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    return real_mutex_trylock(m);
}

int pthread_mutex_unlock(pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_mutex(m);
    return real_mutex_unlock(m);
}

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    LAZY_INIT();
    /* macOS's pthread_mutex_init writes macOS layout; skip it and use
     * glibc's init directly to get a glibc-format mutex. */
    return real_mutex_init(m, a);
}

int pthread_mutex_destroy(pthread_mutex_t *m) {
    LAZY_INIT();
    /* Only destroy if it's a glibc-format mutex (don't touch macOS sig). */
    unsigned int sig = *(unsigned int *)m;
    if (sig != MACOS_PTHREAD_MUTEX_SIG) return real_mutex_destroy(m);
    return 0;
}

int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    LAZY_INIT();
    convert_macos_cond(c);
    convert_macos_mutex(m);
    return real_cond_wait(c, m);
}

int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *ts) {
    LAZY_INIT();
    convert_macos_cond(c);
    convert_macos_mutex(m);
    return real_cond_timedwait(c, m, ts);
}

int pthread_cond_signal(pthread_cond_t *c) {
    LAZY_INIT();
    convert_macos_cond(c);
    return real_cond_signal(c);
}

int pthread_cond_broadcast(pthread_cond_t *c) {
    LAZY_INIT();
    convert_macos_cond(c);
    return real_cond_broadcast(c);
}

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    LAZY_INIT();
    return real_cond_init(c, a);
}

int pthread_cond_destroy(pthread_cond_t *c) {
    LAZY_INIT();
    unsigned int sig = *(unsigned int *)c;
    if (sig != MACOS_PTHREAD_COND_SIG) return real_cond_destroy(c);
    return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rw) {
    LAZY_INIT();
    convert_macos_rwlock(rw);
    return real_rwlock_rdlock(rw);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rw) {
    LAZY_INIT();
    convert_macos_rwlock(rw);
    return real_rwlock_wrlock(rw);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rw) {
    LAZY_INIT();
    convert_macos_rwlock(rw);
    return real_rwlock_unlock(rw);
}

int pthread_rwlock_init(pthread_rwlock_t *rw, const pthread_rwlockattr_t *a) {
    LAZY_INIT();
    return real_rwlock_init(rw, a);
}

int pthread_rwlock_destroy(pthread_rwlock_t *rw) {
    LAZY_INIT();
    unsigned int sig = *(unsigned int *)rw;
    if (sig != MACOS_PTHREAD_RWLOCK_SIG) return real_rwlock_destroy(rw);
    return 0;
}


/* macOS pthread_attr_t is only 16 bytes (long sig + pointer), while glibc's
 * is 56 bytes. When glibc's pthread_attr_init writes 56 bytes into a
 * 16-byte macOS-format buffer, it overflows and corrupts the stack. We
 * allocate a glibc-format attr on the heap and store its pointer in the
 * macOS-format attr (which is big enough to hold a pointer + sig). */

#define MACOS_PTHREAD_ATTR_SIG 0x54485241  /* 'PTHR' — macOS pthread_attr sig */

struct macos_pthread_attr {
    long sig;
    void *opaque;  /* we store the glibc attr pointer here */
};

static int (*real_attr_init)(pthread_attr_t *);
static int (*real_attr_destroy)(pthread_attr_t *);
static int (*real_attr_setstacksize)(pthread_attr_t *, size_t);
static int (*real_attr_getstacksize)(const pthread_attr_t *, size_t *);
static int (*real_attr_setguardsize)(pthread_attr_t *, size_t);

static void init_real_attr_funcs(void) {
    real_attr_init         = dlsym(RTLD_NEXT, "pthread_attr_init");
    real_attr_destroy      = dlsym(RTLD_NEXT, "pthread_attr_destroy");
    real_attr_setstacksize = dlsym(RTLD_NEXT, "pthread_attr_setstacksize");
    real_attr_getstacksize = dlsym(RTLD_NEXT, "pthread_attr_getstacksize");
    real_attr_setguardsize = dlsym(RTLD_NEXT, "pthread_attr_setguardsize");
}

#define LAZY_INIT_ATTR() do { \
    if (!real_attr_init) init_real_attr_funcs(); \
} while (0)

/* Get the glibc attr from a macOS attr. If the macOS attr doesn't have
 * our signature, allocate a new glibc attr. */
static pthread_attr_t *get_glibc_attr(struct macos_pthread_attr *macos_attr) {
    LAZY_INIT_ATTR();
    if (macos_attr->sig != MACOS_PTHREAD_ATTR_SIG || macos_attr->opaque == NULL) {
        /* Not initialized by us — allocate a new glibc attr */
        pthread_attr_t *glibc_attr = calloc(1, sizeof(pthread_attr_t));
        real_attr_init(glibc_attr);
        macos_attr->sig = MACOS_PTHREAD_ATTR_SIG;
        macos_attr->opaque = glibc_attr;
    }
    return (pthread_attr_t *)macos_attr->opaque;
}

int pthread_attr_init(pthread_attr_t *attr) {
    LAZY_INIT_ATTR();
    struct macos_pthread_attr *ma = (struct macos_pthread_attr *)attr;
    pthread_attr_t *glibc_attr = calloc(1, sizeof(pthread_attr_t));
    real_attr_init(glibc_attr);
    ma->sig = MACOS_PTHREAD_ATTR_SIG;
    ma->opaque = glibc_attr;
    return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr) {
    LAZY_INIT_ATTR();
    struct macos_pthread_attr *ma = (struct macos_pthread_attr *)attr;
    if (ma->sig == MACOS_PTHREAD_ATTR_SIG && ma->opaque) {
        real_attr_destroy((pthread_attr_t *)ma->opaque);
        free(ma->opaque);
        ma->opaque = NULL;
        ma->sig = 0;
    }
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setstacksize(glibc_attr, stacksize);
}

int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)(uintptr_t)attr);
    return real_attr_getstacksize(glibc_attr, stacksize);
}

int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize) {
    pthread_attr_t *glibc_attr = get_glibc_attr((struct macos_pthread_attr *)attr);
    return real_attr_setguardsize(glibc_attr, guardsize);
}

/* pthread_create — the macOS binary passes a macOS-format attr. We need
 * to extract the glibc attr from it and pass that to glibc's
 * pthread_create. If the attr is NULL, pass NULL (use default). */
static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                   void *(*)(void *), void *);

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    if (!real_pthread_create) {
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    }
    pthread_attr_t *glibc_attr = NULL;
    if (attr) {
        struct macos_pthread_attr *ma = (struct macos_pthread_attr *)(uintptr_t)attr;
        if (ma->sig == MACOS_PTHREAD_ATTR_SIG) {
            glibc_attr = (pthread_attr_t *)ma->opaque;
        } else {
            /* Attr wasn't initialized by our pthread_attr_init — just pass
             * it through and hope for the best. */
            glibc_attr = (pthread_attr_t *)(uintptr_t)attr;
        }
    }
    return real_pthread_create(thread, glibc_attr, start_routine, arg);
}


/* macOS vs Linux flag translation for libc calls.
 *
 * ripgrep (and other Rust/macOS binaries) call libc functions like mmap,
 * open, madvise, fcntl with macOS flag values. Since these go through
 * glibc (not direct syscalls), our syscall flag translator doesn't see
 * them. We override these functions here to translate flags before
 * delegating to glibc's real implementation.
 */
#include <stdarg.h>

/* mmap flags */
#define MACOS_MAP_ANON        0x1000
#define LINUX_MAP_ANONYMOUS   0x0020

/* open flags */
#define MACOS_O_CREAT         0x0200
#define MACOS_O_EXCL          0x0800
#define MACOS_O_TRUNC         0x0400
#define MACOS_O_APPEND        0x0008
#define MACOS_O_NONBLOCK      0x0004
#define MACOS_O_NOCTTY        0x10000
#define MACOS_O_SYNC          0x0080
#define MACOS_O_CLOEXEC       0x1000000
#define MACOS_O_DIRECTORY     0x100000
#define MACOS_O_NOFOLLOW      0x0100

#define LINUX_O_CREAT         0x0040
#define LINUX_O_EXCL          0x0080
#define LINUX_O_TRUNC         0x0200
#define LINUX_O_APPEND        0x0400
#define LINUX_O_NONBLOCK      0x0800
#define LINUX_O_NOCTTY        0x0100
#define LINUX_O_SYNC          0x101000
#define LINUX_O_CLOEXEC       0x80000
#define LINUX_O_DIRECTORY     0x10000
#define LINUX_O_NOFOLLOW      0x20000

/* madvise advice */
#define MACOS_MADV_FREE       5
#define LINUX_MADV_FREE       8

/* fcntl commands — macOS values that differ from Linux */
#define MACOS_F_GETLK         7
#define MACOS_F_SETLK         8
#define MACOS_F_SETLKW        9
#define MACOS_F_DUPFD_CLOEXEC 67
#define LINUX_F_GETLK         5
#define LINUX_F_SETLK         6
#define LINUX_F_SETLKW        7
#define LINUX_F_DUPFD_CLOEXEC 1030
/* F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4 are the same on both */

static unsigned int translate_open_flags(unsigned int macos_flags) {
    unsigned int linux_flags = macos_flags & 0x3;  /* O_RDONLY/O_WRONLY/O_RDWR are the same */
    if (macos_flags & MACOS_O_CREAT)     linux_flags |= LINUX_O_CREAT;
    if (macos_flags & MACOS_O_EXCL)      linux_flags |= LINUX_O_EXCL;
    if (macos_flags & MACOS_O_TRUNC)     linux_flags |= LINUX_O_TRUNC;
    if (macos_flags & MACOS_O_APPEND)    linux_flags |= LINUX_O_APPEND;
    if (macos_flags & MACOS_O_NONBLOCK)  linux_flags |= LINUX_O_NONBLOCK;
    if (macos_flags & MACOS_O_NOCTTY)    linux_flags |= LINUX_O_NOCTTY;
    if (macos_flags & MACOS_O_SYNC)      linux_flags |= LINUX_O_SYNC;
    if (macos_flags & MACOS_O_CLOEXEC)   linux_flags |= LINUX_O_CLOEXEC;
    if (macos_flags & MACOS_O_DIRECTORY) linux_flags |= LINUX_O_DIRECTORY;
    if (macos_flags & MACOS_O_NOFOLLOW)  linux_flags |= LINUX_O_NOFOLLOW;
    return linux_flags;
}

static int translate_fcntl_cmd(int cmd) {
    switch (cmd) {
        case MACOS_F_GETLK:         return LINUX_F_GETLK;
        case MACOS_F_SETLK:         return LINUX_F_SETLK;
        case MACOS_F_SETLKW:        return LINUX_F_SETLKW;
        case MACOS_F_DUPFD_CLOEXEC: return LINUX_F_DUPFD_CLOEXEC;
        default: return cmd;  /* F_DUPFD/F_GETFD/F_SETFD/F_GETFL/F_SETFL are the same */
    }
}

static void * (*real_mmap)(void *, size_t, int, int, int, off_t);
static int    (*real_open)(const char *, int, ...);
static int    (*real_madvise)(void *, size_t, int);
static int    (*real_fcntl)(int, int, ...);
static int    (*real_mprotect)(void *, size_t, int);

static void init_real_io_funcs(void) {
    real_mmap     = dlsym(RTLD_NEXT, "mmap");
    real_open     = dlsym(RTLD_NEXT, "open");
    real_madvise  = dlsym(RTLD_NEXT, "madvise");
    real_fcntl    = dlsym(RTLD_NEXT, "fcntl");
    real_mprotect = dlsym(RTLD_NEXT, "mprotect");
}

#define LAZY_INIT_IO() do { \
    if (!real_mmap) init_real_io_funcs(); \
} while (0)

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    LAZY_INIT_IO();
    void *orig_addr = addr;  /* save the original requested address */
    /* Translate MAP_ANON (macOS) -> MAP_ANONYMOUS (Linux). Other flags
     * (MAP_PRIVATE, MAP_SHARED, MAP_FIXED) have the same values. */
    int orig_flags = flags;
    if (flags & MACOS_MAP_ANON) {
        flags = (flags & ~MACOS_MAP_ANON) | LINUX_MAP_ANONYMOUS;
        fd = -1;  /* MAP_ANONYMOUS requires fd=-1 on Linux */
    }
    /* Linux requires page-aligned addr when MAP_FIXED is set; macOS is
     * more lenient and rounds down. The Rust runtime computes guard page
     * addresses that aren't page-aligned (based on the current stack
     * pointer), so we replicate macOS's rounding behavior. */
    if ((flags & 0x10 /* MAP_FIXED */) && addr != NULL) {
        size_t page_size = sysconf(_SC_PAGESIZE);
        uintptr_t a = (uintptr_t)addr;
        size_t adjustment = a % page_size;
        if (adjustment != 0) {
            addr = (void *)(a - adjustment);
            length += adjustment;
            if (offset != 0) offset -= adjustment;  /* keep file mapping aligned */
        }
    }
    void *result = real_mmap(addr, length, prot, flags, fd, offset);
    if (result == (void *)-1) {
        /* If MAP_FIXED failed, the region might already be mapped (e.g.,
         * within the main thread's stack). Return the requested address
         * as if the mmap succeeded. The memory is already accessible. */
        if ((orig_flags & 0x10 /* MAP_FIXED */) && orig_addr != NULL) {
            return orig_addr;
        }
    } else if ((orig_flags & 0x10 /* MAP_FIXED */) && result != orig_addr) {
        /* mmap returned a different address than requested (because we
         * rounded down). Return the original requested address so the
         * caller sees the expected value. */
        return orig_addr;
    }
    return result;
}

int open(const char *pathname, int flags, ...) {
    LAZY_INIT_IO();
    int linux_flags = (int)translate_open_flags((unsigned int)flags);
    mode_t mode = 0;
    if (linux_flags & LINUX_O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return real_open(pathname, linux_flags, mode);
}

int madvise(void *addr, size_t length, int advice) {
    LAZY_INIT_IO();
    if (advice == MACOS_MADV_FREE) advice = LINUX_MADV_FREE;
    return real_madvise(addr, length, advice);
}

int mprotect(void *addr, size_t len, int prot) {
    LAZY_INIT_IO();
    /* PROT_* values are the same on macOS and Linux, but Linux requires
     * page-aligned addr. Round down like we do for mmap. */
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t a = (uintptr_t)addr;
    size_t adjustment = a % page_size;
    if (adjustment != 0) {
        addr = (void *)(a - adjustment);
        len += adjustment;
    }
    return real_mprotect(addr, len, prot);
}

int fcntl(int fd, int cmd, ...) {
    LAZY_INIT_IO();
    int linux_cmd = translate_fcntl_cmd(cmd);
    /* Commands that take no argument: F_GETFD (1), F_GETFL (3).
     * All other commands take an int or pointer argument. */
    if (cmd == 1 || cmd == 3) {
        return real_fcntl(fd, linux_cmd);
    }
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return real_fcntl(fd, linux_cmd, arg);
}

/* macOS strerror_r returns int (0 on success, errno on failure) — the XSI
 * version. glibc with _GNU_SOURCE provides the GNU version that returns
 * char*. Rust (compiled for macOS) checks the return as int and panics
 * ("strerror_r failure") when it's non-zero. We override the symbol via
 * asm alias to avoid the conflicting _GNU_SOURCE declaration, and
 * implement the XSI semantics using glibc's thread-safe strerror. */
extern char *__strerror_r(int errnum, char *buf, size_t buflen);
int macify_strerror_r(int errnum, char *buf, size_t buflen) __asm__("strerror_r");
int macify_strerror_r(int errnum, char *buf, size_t buflen) {
    /* __strerror_r is glibc's internal GNU version (returns char*).
     * If it returns a pointer != buf, the string is in static storage
     * and we copy it into buf. Then return 0 (XSI success). */
    char *str = __strerror_r(errnum, buf, buflen);
    if (str && str != buf) {
        size_t len = strlen(str);
        if (len >= buflen) len = buflen - 1;
        memcpy(buf, str, len);
        buf[len] = '\0';
    }
    return 0;
}


/* macOS struct sigaction has a completely different layout from Linux's.
 * macOS: sa_handler(8) + sa_mask(4, uint32) + sa_flags(4) = ~16 bytes
 * Linux: sa_handler(8) + sa_flags(8) + sa_mask(128) + sa_restorer(8) = ~144 bytes
 *
 * When glibc's sigaction reads a macOS-format struct, it reads 128 bytes
 * for sa_mask from a 4-byte field, corrupting the stack. This caused
 * ripgrep to crash with a NULL function pointer call after sigaction
 * overwrote stack variables.
 *
 * We override sigaction to translate the struct layout. Also override
 * sigprocmask/pthread_sigmask for the same sigset_t size mismatch. */
#include <signal.h>

/* macOS sigaction layout (x86_64):
 *   offset 0:  handler/sigaction function pointer (8 bytes)
 *   offset 8:  sa_mask (4 bytes, sigset_t = uint32_t)
 *   offset 12: sa_flags (4 bytes)
 * We access fields by offset to avoid macro conflicts with glibc's
 * struct sigaction field names. */
struct macos_sigaction {
    void (*handler)(int);    /* offset 0 */
    uint32_t mask;           /* offset 8 */
    int flags;               /* offset 12 */
};

static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);

/* Saved Rust signal handlers — we chain to these after printing crash info. */
static void (*rust_segv_handler)(int) = NULL;
static void (*rust_bus_handler)(int) = NULL;

/* Our crash proxy — prints info then chains to Rust's handler. */
static void crash_proxy_segv(int sig, siginfo_t *info, void *uctx) {
    /* Print minimal crash info to stderr */
    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "\nmacify: CRASH (proxied) sig=%d fault_addr=%p rip=%#lx rsp=%#lx\n"
        "  rax=%#lx rbx=%#lx rcx=%#lx rdx=%#lx rdi=%#lx rsi=%#lx\n",
        sig, info->si_addr,
        (unsigned long)regs[REG_RIP], (unsigned long)regs[REG_RSP],
        (unsigned long)regs[REG_RAX], (unsigned long)regs[REG_RBX],
        (unsigned long)regs[REG_RCX], (unsigned long)regs[REG_RDX],
        (unsigned long)regs[REG_RDI], (unsigned long)regs[REG_RSI]);
    write(2, buf, n);
    /* Dump first 16 stack entries */
    uint64_t *sp = (uint64_t *)regs[REG_RSP];
    for (int s = 0; s < 16; s++) {
        uint64_t addr = (uint64_t)(sp + s);
        if (addr < 0x10000 || addr > 0x7fffffffffffUL) continue;
        n = snprintf(buf, sizeof(buf), "  rsp+0x%-2x: %#018lx\n",
                     s * 8, (unsigned long)sp[s]);
        write(2, buf, n);
    }
    _exit(128 + sig);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (!real_sigaction) {
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");
    }
    struct sigaction linux_act;
    struct sigaction linux_oldact;
    struct sigaction *p_linux_act = NULL;
    struct sigaction *p_linux_oldact = NULL;

    if (act) {
        struct macos_sigaction *macos_act = (struct macos_sigaction *)act;
        memset(&linux_act, 0, sizeof(linux_act));
        linux_act.sa_handler = macos_act->handler;
        linux_act.sa_flags = macos_act->flags;
        sigemptyset(&linux_act.sa_mask);
        if (macos_act->mask) {
            memcpy(&linux_act.sa_mask, &macos_act->mask, sizeof(uint32_t));
        }
        /* If the Rust runtime is installing a SIGSEGV/SIGBUS handler,
         * silently ignore it — our loader's crash handler stays active
         * so we can debug crashes. The Rust runtime's handler would
         * try to print a panic message, but since the runtime isn't
         * fully initialized, it just crashes silently. */
        if (signum == SIGSEGV || signum == SIGBUS) {
            if (oldact) {
                /* Return the current (our) handler as the "old" handler */
                p_linux_oldact = &linux_oldact;
                real_sigaction(signum, NULL, p_linux_oldact);
            }
            return 0;  /* pretend success without installing */
        }
        p_linux_act = &linux_act;
    }
    if (oldact) {
        p_linux_oldact = &linux_oldact;
    }

    int result = real_sigaction(signum, p_linux_act, p_linux_oldact);

    if (oldact && result == 0) {
        struct macos_sigaction *macos_old = (struct macos_sigaction *)oldact;
        macos_old->handler = linux_oldact.sa_handler;
        macos_old->flags = linux_oldact.sa_flags;
        uint32_t macos_mask = 0;
        memcpy(&macos_mask, &linux_oldact.sa_mask, sizeof(uint32_t));
        macos_old->mask = macos_mask;
    }
    return result;
}

/* signal() — glibc's signal() calls __sigaction internally, bypassing our
 * sigaction override. The Rust runtime calls signal(SIGSEGV, ...) which
 * would override our crash handler. We intercept signal() for SIGSEGV/
 * SIGBUS and pretend success without actually installing. */
sighandler_t macify_signal(int signum, sighandler_t handler) __asm__("signal");
sighandler_t macify_signal(int signum, sighandler_t handler) {
    if (signum == SIGSEGV || signum == SIGBUS) {
        return SIG_DFL;  /* pretend the old handler was SIG_DFL */
    }
    /* For other signals, delegate to glibc */
    static sighandler_t (*real_signal)(int, sighandler_t) = NULL;
    if (!real_signal) real_signal = dlsym(RTLD_NEXT, "signal");
    return real_signal(signum, handler);
}

/* sigaltstack: the Rust runtime sets up an alternate signal stack for
 * stack overflow detection. If the alternate stack is in a bad location
 * (e.g., our mmap override returned a slightly wrong address), the
 * signal handler crashes immediately without printing anything. We make
 * this a no-op so signal handlers run on the default stack. */
int macify_sigaltstack(const stack_t *ss, stack_t *oss) __asm__("sigaltstack");
int macify_sigaltstack(const stack_t *ss, stack_t *oss) {
    (void)ss; (void)oss;
    return 0;  /* pretend success */
}

/* sigprocmask: macOS sigset_t = 4 bytes, Linux = 128 bytes.
 * The how parameter also differs: macOS SIG_BLOCK=1, SIG_UNBLOCK=2,
 * SIG_SETMASK=3; Linux SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2. */
static int (*real_sigprocmask)(int, const sigset_t *, sigset_t *);

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (!real_sigprocmask) {
        real_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");
    }
    /* Translate macOS 'how' to Linux 'how' */
    int linux_how;
    switch (how) {
        case 1: linux_how = SIG_BLOCK; break;    /* macOS SIG_BLOCK = 1 */
        case 2: linux_how = SIG_UNBLOCK; break;  /* macOS SIG_UNBLOCK = 2 */
        case 3: linux_how = SIG_SETMASK; break;  /* macOS SIG_SETMASK = 3 */
        default: linux_how = how; break;
    }

    sigset_t linux_set;
    sigset_t linux_oldset;
    sigset_t *p_set = NULL;
    sigset_t *p_oldset = NULL;

    if (set) {
        /* set points to a macOS 4-byte sigset; convert to Linux 128-byte */
        memset(&linux_set, 0, sizeof(linux_set));
        memcpy(&linux_set, set, sizeof(uint32_t));
        p_set = &linux_set;
    }
    if (oldset) {
        p_oldset = &linux_oldset;
    }

    int result = real_sigprocmask(linux_how, p_set, p_oldset);

    if (oldset && result == 0) {
        /* Convert Linux 128-byte back to macOS 4-byte */
        memcpy(oldset, &linux_oldset, sizeof(uint32_t));
    }
    return result;
}

/* pthread_sigmask has the same issue as sigprocmask */
static int (*real_pthread_sigmask)(int, const sigset_t *, sigset_t *);

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (!real_pthread_sigmask) {
        real_pthread_sigmask = dlsym(RTLD_NEXT, "pthread_sigmask");
    }
    int linux_how;
    switch (how) {
        case 1: linux_how = SIG_BLOCK; break;
        case 2: linux_how = SIG_UNBLOCK; break;
        case 3: linux_how = SIG_SETMASK; break;
        default: linux_how = how; break;
    }
    sigset_t linux_set;
    sigset_t linux_oldset;
    sigset_t *p_set = NULL;
    sigset_t *p_oldset = NULL;
    if (set) {
        memset(&linux_set, 0, sizeof(linux_set));
        memcpy(&linux_set, set, sizeof(uint32_t));
        p_set = &linux_set;
    }
    if (oldset) p_oldset = &linux_oldset;
    int result = real_pthread_sigmask(linux_how, p_set, p_oldset);
    if (oldset && result == 0) {
        memcpy(oldset, &linux_oldset, sizeof(uint32_t));
    }
    return result;
}


/* macOS dlsym uses RTLD_DEFAULT = (void*)-2, but glibc uses RTLD_DEFAULT = NULL.
 * When the Rust runtime calls dlsym(RTLD_DEFAULT, "symbol"), glibc crashes
 * trying to dereference -2 as a handle. We translate macOS's RTLD_DEFAULT
 * to glibc's RTLD_DEFAULT (NULL) and macOS's RTLD_SELF (-3) similarly. */
#define MACOS_RTLD_DEFAULT ((void *)-2)
#define MACOS_RTLD_SELF    ((void *)-3)
/* RTLD_NEXT = -1 is the same on both platforms */

static void *(*real_dlsym)(void *, const char *);

void *dlsym(void *handle, const char *symbol) {
    if (!real_dlsym) {
        real_dlsym = dlsym(RTLD_NEXT, "dlsym");
    }
    if (handle == MACOS_RTLD_DEFAULT || handle == MACOS_RTLD_SELF) {
        handle = NULL;  /* glibc's RTLD_DEFAULT */
    }
    return real_dlsym(handle, symbol);
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

