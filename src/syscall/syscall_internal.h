/* syscall_internal.h — internal declarations for src/syscall/ */
#ifndef SYSCALL_INTERNAL_H
#define SYSCALL_INTERNAL_H

#include "../macify.h"

#define BSD_SYSCALL_MAX 600

/* Argument translation flags.
 *
 * Invariant: every bit must be unique. These are OR'd together per-syscall
 * in bsd_arg_flags[] and tested independently in sigill_handler().
 * ARG_SIGALTSTACK previously collided with ARG_SIGACTION (both 0x20),
 * making each call site run the other's struct translation.
 * bsd_arg_flags[] is uint16_t so bits beyond 0x80 are available. */
#define ARG_OPEN_FLAGS    0x0001
#define ARG_MMAP_FLAGS    0x0002
#define ARG_FCNTL_CMD     0x0004
#define ARG_KILL_SIGNAL   0x0008
#define ARG_MADVISE       0x0010
#define ARG_SIGACTION     0x0020
#define ARG_SIGPROCMASK   0x0040
#define ARG_FORCE_SLOW    0x0080
#define ARG_SIGALTSTACK   0x0100

/* Syscall table */
extern const int16_t bsd_to_linux[BSD_SYSCALL_MAX];
extern const uint16_t bsd_arg_flags[BSD_SYSCALL_MAX];

/* Flag translation functions */
int translate_open_flags(int macos_flags);
int translate_mmap_flags(int macos_flags);
int translate_kill_signal(int macos_sig);
int translate_fcntl_cmd(int macos_cmd);
int translate_madvise(int macos_advice);

/* Raw syscall */
long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6);

/* Stats */
void print_stats(void);

/* Global counters */
extern unsigned long g_slow_path_calls;
extern unsigned long g_fast_path_sites;
extern unsigned long g_slow_path_sites;

#define BACKWARD_SCAN_BYTES 32
void sigill_handler_pre_resolve(void);

/* macOS-specific fcntl commands (values from xnu bsd/sys/fcntl.h).
 * Handled with execution logic in sigill_handler(), not cmd remapping. */
#define MACOS_F_RDADVISE       44
#define MACOS_F_RDAHEAD        45
#define MACOS_F_NOCACHE        48
#define MACOS_F_GETPATH        50
#define MACOS_F_FULLFSYNC      51
#define MACOS_F_GLOBAL_NOCACHE 55
#define MACOS_F_SETNOSIGPIPE   73
#define MACOS_F_GETNOSIGPIPE   74

#endif /* SYSCALL_INTERNAL_H */
