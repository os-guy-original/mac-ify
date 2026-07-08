#!/usr/bin/env python3
"""Split shim/libmacify_shim.c into smaller files in shim/ directory.

Reads the original monolithic file and extracts sections into:
  shim.h        — shared header (includes, types, globals, macros)
  shim_core.c   — errno, progname, stack_chk, dyld, NSGet*
  shim_mach.c   — Mach trap stubs
  shim_objc.c   — ObjC runtime stubs
  shim_tlv.c    — TLV (thread-local variables)
  shim_pthread.c — pthread overrides
  shim_signal.c — signal handling + crash handler
  shim_io.c     — I/O flag translation + dlsym
  shim_misc.c   — everything else
"""
import re

SRC = "/home/z/my-project/mac-ify/shim/libmacify_shim.c"

with open(SRC, "r") as f:
    lines = f.readlines()

# Line numbers are 1-indexed in the plan; convert to 0-indexed slices
def L(start, end):
    """Extract lines start..end (1-indexed, inclusive)."""
    return "".join(lines[start-1:end])

# ── shim.h ──────────────────────────────────────────────────────────
SHIM_H = """\
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

/* shim_pthread.c — our allocated stack info (set by the loader) */
extern void *macify_main_stack_base;
extern size_t macify_main_stack_size;

/* shim_signal.c */
extern int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);
void macify_crash_handler(int sig, siginfo_t *info, void *uctx);

/* shim_io.c */
extern void *(*real_dlsym)(void *, const char *);

/* shim_misc.c — rune/locale tables */
extern uint32_t macify_runetype[256];
extern int16_t macify_maplower[256];
extern int16_t macify_mapupper[256];

/* ── Shared macros ────────────────────────────────────────────── */

/* macOS pthread synchronization object signatures */
#define MACOS_PTHREAD_MUTEX_SIG  0x32AAABA7u
#define MACOS_PTHREAD_COND_SIG   0x3CB0B5BBu
#define MACOS_PTHREAD_RWLOCK_SIG 0x2DA8B3B4u
#define MACOS_PTHREAD_ATTR_SIG   0x54485241
#define MACOS_PTHREAD_ONCE_INIT  0x30B1BCBA
#define MACIFY_MAX_KEYS 256

#endif /* MACIFY_SHIM_H */
"""

# ── shim_core.c ────────────────────────────────────────────────────
# errno, progname, stack_chk, dyld, NSGet*, stdio globals
SHIM_CORE = '#include "shim.h"\n\n' + \
    L(47, 145) + \
    L(295, 317) + \
    L(682, 718)

# ── shim_mach.c ────────────────────────────────────────────────────
SHIM_MACH = '#include "shim.h"\n\n' + \
    L(154, 173) + \
    L(458, 479)

# ── shim_objc.c ────────────────────────────────────────────────────
SHIM_OBJC = '#include "shim.h"\n\n' + \
    L(221, 258)

# ── shim_tlv.c ─────────────────────────────────────────────────────
# TLV: tlv_descriptor (in header now), bootstrap, set_tlv_info, _tlv_atexit
# Skip lines 552-556 (struct tlv_descriptor definition — now in shim.h)
_tlv_text = L(451, 456) + L(558, 680)
SHIM_TLV = '#include "shim.h"\n\n' + _tlv_text

# ── shim_pthread.c ─────────────────────────────────────────────────
# pthread overrides: mutex/cond/rwlock, attr, create, once, TLS, stack*_np
# Note: macify_main_stack_base/size are 'static' in the original — we need
# to change them to non-static. Also remove struct/define now in shim.h.
_pthread_text = L(182, 184) + L(494, 540) + L(1037, 1408)
# Change 'static void *macify_main_stack_base' to non-static
_pthread_text = _pthread_text.replace(
    'static void *macify_main_stack_base = NULL;',
    'void *macify_main_stack_base = NULL;')
_pthread_text = _pthread_text.replace(
    'static size_t macify_main_stack_size = 0;',
    'size_t macify_main_stack_size = 0;')
# Remove struct macos_pthread_attr and #define (now in shim.h)
_pthread_text = _pthread_text.replace(
    '#define MACOS_PTHREAD_ATTR_SIG 0x54485241  /* \'PTHR\' — macOS pthread_attr sig */\n\n'
    'struct macos_pthread_attr {\n'
    '    long sig;\n'
    '    void *opaque;  /* we store the glibc attr pointer here */\n'
    '};\n\n', '')
SHIM_PTHREAD = '#include "shim.h"\n\n' + _pthread_text

# ── shim_signal.c ──────────────────────────────────────────────────
# sigaction, signal, sigprocmask, pthread_sigmask, sigset ops, sigaltstack,
# crash handler, macify_init_stdio constructor
# Note: real_sigaction is 'static' in the original — change to non-static
# for the extern declaration in shim.h. Also remove the forward declaration
# of macify_crash_handler (now in shim.h) and struct macos_sigaction (in shim.h).
_signal_text = L(319, 361) + L(1668, 1934)
# Remove the forward declaration (lines 319-320 in original)
_signal_text = _signal_text.replace(
    '/* Forward declaration — defined later in the sigaction section */\n'
    'static void macify_crash_handler(int sig, siginfo_t *info, void *uctx);\n\n',
    '')
# Change 'static int (*real_sigaction)' to non-static
_signal_text = _signal_text.replace(
    'static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);',
    'int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);')
# Remove struct macos_sigaction (now in shim.h)
_signal_text = _signal_text.replace(
    'struct macos_sigaction {\n'
    '    void (*handler)(int);    /* offset 0 */\n'
    '    uint32_t mask;           /* offset 8 */\n'
    '    int flags;               /* offset 12 */\n'
    '};\n\n', '')
# Change 'static void macify_crash_handler' to non-static (extern in shim.h)
_signal_text = _signal_text.replace(
    'static void macify_crash_handler(',
    'void macify_crash_handler(')
SHIM_SIGNAL = '#include "shim.h"\n\n' + _signal_text

# ── shim_io.c ──────────────────────────────────────────────────────
# mmap, mprotect, munmap, open, madvise, fcntl, strerror_r, dlsym
# Note: real_dlsym is 'static' — change to non-static
_io_text = L(1411, 1665) + L(1937, 2014)
_io_text = _io_text.replace(
    'static void *(*real_dlsym)(void *, const char *);',
    'void *(*real_dlsym)(void *, const char *);')
SHIM_IO = '#include "shim.h"\n\n' + _io_text

# ── shim_misc.c ────────────────────────────────────────────────────
# Everything else: chkstk, rune locale, dispatch, CF, Unwind, math, etc.
# Note: TLS functions (1037+) are in shim_pthread.c, so stop at 1034.
_misc_text = \
    L(193, 212) + \
    L(260, 291) + \
    L(363, 443) + \
    L(481, 492) + \
    L(727, 861) + \
    L(870, 1034) + \
    L(2017, 2034)
# Change 'static uint32_t macify_runetype' to non-static (extern in header)
_misc_text = _misc_text.replace(
    'static uint32_t macify_runetype[256];',
    'uint32_t macify_runetype[256];')
_misc_text = _misc_text.replace(
    'static int16_t macify_maplower[256];',
    'int16_t macify_maplower[256];')
_misc_text = _misc_text.replace(
    'static int16_t macify_mapupper[256];',
    'int16_t macify_mapupper[256];')
SHIM_MISC = '#include "shim.h"\n\n' + _misc_text

# ── Write all files ────────────────────────────────────────────────
import os
OUT_DIR = "/home/z/my-project/mac-ify/shim"

files = {
    "shim.h": SHIM_H,
    "shim_core.c": SHIM_CORE,
    "shim_mach.c": SHIM_MACH,
    "shim_objc.c": SHIM_OBJC,
    "shim_tlv.c": SHIM_TLV,
    "shim_pthread.c": SHIM_PTHREAD,
    "shim_signal.c": SHIM_SIGNAL,
    "shim_io.c": SHIM_IO,
    "shim_misc.c": SHIM_MISC,
}

for name, content in files.items():
    path = os.path.join(OUT_DIR, name)
    with open(path, "w") as f:
        f.write(content)
    line_count = content.count('\n')
    print(f"  {name}: {line_count} lines")

# ── Update Makefile ────────────────────────────────────────────────
MAKEFILE = """\
# Mac-ify libSystem shim Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -fPIC
LDFLAGS ?= -shared -lpthread -ldl -lm

BIN_DIR  = ../build
LIB      = $(BIN_DIR)/libmacify_shim.so

SRC = shim_core.c shim_mach.c shim_objc.c shim_tlv.c shim_pthread.c \\
      shim_signal.c shim_io.c shim_misc.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJ) | $(BIN_DIR)
\t$(CC) $(CFLAGS) -shared -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c shim.h
\t$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR):
\tmkdir -p $(BIN_DIR)

clean:
\trm -f $(LIB) $(OBJ)
"""
with open(os.path.join(OUT_DIR, "Makefile"), "w") as f:
    f.write(MAKEFILE)
print(f"  Makefile: updated")

print(f"\nDone! Split into {len(files)} files.")
print(f"Original: {len(lines)} lines")
total = sum(c.count('\n') for c in files.values())
print(f"Total in split files: {total} lines")
