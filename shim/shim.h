/* shim.h — shared header for the mac-ify libSystem shim. */
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

/* ── Helper: lazy-load a glibc function ─────────────────────────
 * Usage: REAL_FUNC(write, ssize_t, (int fd, const void *buf, size_t n))
 * Expands to a static pointer that's resolved on first use via dlsym. */
#define REAL_FUNC(name, ret, args) \
    static ret (*real_##name)args = NULL; \
    if (!real_##name) real_##name = dlsym(RTLD_NEXT, #name)

#define REAL_FUNC_DECL(name, ret, args) \
    static ret (*real_##name)args

/* ── Types ── */

struct tlv_descriptor {
    void *(*thunk)(struct tlv_descriptor *);
    void *key;
    unsigned long offset;
};

struct macos_sigaction {
    void (*handler)(int);
    uint32_t mask;
    int flags;
};

struct macos_pthread_attr {
    long sig;
    void *opaque;
};

/* ── Globals ── */

extern char **environ;
extern char *___progname;
extern char *__progname;
extern uintptr_t __stack_chk_guard;
extern uintptr_t _STACK_CHK_GUARD;
extern FILE *__stderrp, *__stdinp, *__stdoutp;
extern void *macify_main_stack_base;
extern size_t macify_main_stack_size;
extern void *(*real_dlsym)(void *, const char *);
extern uintptr_t macify_text_lo, macify_text_hi;
extern uint32_t macify_runetype[256];
extern int16_t macify_maplower[256], macify_mapupper[256];

/* ── Functions ── */

int macify_linux_to_macos_errno(int linux_errno);
void __macify_set_text_range(uint64_t lo, uint64_t hi);
int macify_caller_is_macos_text(void *ret_addr);
void macify_crash_handler(int sig, siginfo_t *info, void *uctx);

/* ── Constants ── */

#define MACOS_PTHREAD_MUTEX_SIG  0x32AAABA7u
#define MACOS_PTHREAD_COND_SIG   0x3CB0B5BBu
#define MACOS_PTHREAD_RWLOCK_SIG 0x2DA8B3B4u
#define MACOS_PTHREAD_ATTR_SIG   0x54485241u
#define MACOS_PTHREAD_ONCE_INIT  0x30B1BCBAu
#define MACIFY_MAX_KEYS 256

#endif
