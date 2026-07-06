/* shim.h — shared header for the mac-ify libSystem shim.
 *
 * All shim_*.c files include this. It provides common includes,
 * shared types, extern declarations for cross-file globals, and
 * macOS/Linux ABI constants.
 */
#ifndef MACIFY_SHIM_H
#define MACIFY_SHIM_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <sys/stat.h>
#include <spawn.h>
#include <time.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <ucontext.h>
#include <ctype.h>
#include <dlfcn.h>
#include <math.h>
#include <stdarg.h>
#include <link.h>
#include <elf.h>

/* ── Shared types ─────────────────────────────────────────────── */

/* macOS TLV descriptor (x86_64). Code accesses a TLV by calling
 * desc->thunk(desc), which returns a pointer to the variable's storage. */
struct tlv_descriptor {
    void *(*thunk)(struct tlv_descriptor *);
    void *key;
    unsigned long offset;
};

/* macOS struct sigaction layout (x86_64):
 *   offset 0:  handler function pointer (8 bytes)
 *   offset 8:  sa_mask (4 bytes, sigset_t = uint32_t)
 *   offset 12: sa_flags (4 bytes)
 * Linux's is ~144 bytes with a 128-byte sa_mask. */
struct macos_sigaction {
    void (*handler)(int);
    uint32_t mask;
    int flags;
};

/* macOS pthread_attr_t is 16 bytes (long sig + pointer); glibc's is 56.
 * We store a heap-allocated glibc attr pointer in the macOS struct. */
struct macos_pthread_attr {
    long sig;
    void *opaque;
};

/* ── Shared globals (extern — defined in their respective .c files) ── */

/* shim_core.c */
extern char **environ;
extern char *___progname;
extern char *__progname;
extern uintptr_t __stack_chk_guard;
extern uintptr_t _STACK_CHK_GUARD;
extern FILE *__stderrp;
extern FILE *__stdinp;
extern FILE *__stdoutp;

/* Linux → macOS errno translator (defined in shim_core.c). Call this
 * before returning -1 from any shim function that wraps a Linux syscall
 * whose errno is then read by the macOS binary. */
int macify_linux_to_macos_errno(int linux_errno);

/* shim_pthread.c — our allocated stack info (set by the loader) */
extern void *macify_main_stack_base;
extern size_t macify_main_stack_size;

/* shim_signal.c */
extern int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);
void macify_crash_handler(int sig, siginfo_t *info, void *uctx);

/* shim_io.c */
extern void *(*real_dlsym)(void *, const char *);

/* __TEXT range of the loaded macOS main image, set by the loader via
 * __macify_set_text_range(). Used by the network shim functions to decide
 * whether to translate Linux errno → macOS errno before returning.
 *
 * Background: errno translation is needed when the macOS binary reads errno
 * directly (it expects macOS errno values). But when a Linux library such
 * as libgnutls.so.30 calls our shim (because we override the global symbol,
 * e.g. for `recv`), the Linux library expects Linux errno values. If we
 * translate the errno in that case, EAGAIN (Linux 11) becomes 35 (macOS
 * EAGAIN), which on Linux is EDEADLK — GnuTLS misreads this as a fatal
 * error and the TLS handshake stalls forever.
 *
 * Heuristic: if `__builtin_return_address(0)` (the address of the
 * instruction immediately after the `call` site) is inside the macOS
 * binary's __TEXT segment, the caller is the macOS binary and we translate
 * errno. Otherwise the caller is a Linux library and we leave errno alone. */
extern uintptr_t macify_text_lo;
extern uintptr_t macify_text_hi;
void __macify_set_text_range(uint64_t lo, uint64_t hi);

/* Returns 1 if the immediate caller (by return address) is the macOS main
 * image's __TEXT segment. Used to gate errno translation. */
int macify_caller_is_macos_text(void *ret_addr);

/* Returns our shim's override for a given symbol, or NULL if we don't
 * override it. Used by dl.c's dlsym to ensure Go gets our translated
 * signal functions instead of glibc's. */
void *macify_get_shim_symbol(const char *symbol);

/* shim_misc.c — rune/locale tables */
extern uint32_t macify_runetype[256];
extern int16_t macify_maplower[256];
extern int16_t macify_mapupper[256];

/* ── Shared macros ────────────────────────────────────────────── */

/* macOS pthread synchronization object signatures */
#define MACOS_PTHREAD_MUTEX_SIG  0x32AAABA7u
#define MACOS_PTHREAD_COND_SIG   0x3CB0B5BBu
#define MACOS_PTHREAD_RWLOCK_SIG 0x2DA8B3B4u
#define MACOS_PTHREAD_ATTR_SIG   0x54485244u
#define MACOS_PTHREAD_ONCE_INIT  0x30B1BCBA
#define MACIFY_MAX_KEYS 256

/* ── Fake CoreFoundation object tag values ──────────────────────
 * Used by cf.c, objc_compat.c, and any other file that creates or
 * inspects fake CF objects (CFString, CFArray, CFDictionary, etc.). */
#define SC_TAG_STRING     0x5C01  /* fake CFString */
#define SC_TAG_ARRAY      0x5C02  /* fake CFArray */
#define SC_TAG_DICT       0x5C03  /* fake CFDictionary */
#define SC_TAG_STORE      0x5C04  /* fake SCDynamicStoreRef */

struct sc_obj {
    uint32_t tag;       /* one of SC_TAG_* */
    uint32_t count;     /* element count for arrays/dicts, byte count for strings */
    void *data;         /* payload (string, or array of pointers) */
};

#endif /* MACIFY_SHIM_H */

/* Errno translation: use at end of functions returning -1 on error */
#define TRANSLATE_ERRNO(r) do { \
    if ((r) == -1 && macify_caller_is_macos_text(__builtin_return_address(0))) \
        errno = macify_linux_to_macos_errno(errno); \
} while (0)

/* TRANSLATE_ERRNO_SAVED — like TRANSLATE_ERRNO but uses saved errno */
#define TRANSLATE_ERRNO_SAVED(r, saved) do { \
    if ((r) == -1 && macify_caller_is_macos_text(__builtin_return_address(0))) \
        errno = macify_linux_to_macos_errno(saved); \
} while (0)
