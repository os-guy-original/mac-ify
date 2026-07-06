/* syscall_internal.h — internal declarations for src/syscall/ */
#ifndef SYSCALL_INTERNAL_H
#define SYSCALL_INTERNAL_H

#include "../macify.h"

#define BSD_SYSCALL_MAX 600

/* Argument translation flags */
#define ARG_OPEN_FLAGS    0x01
#define ARG_MMAP_FLAGS    0x02
#define ARG_FCNTL_CMD     0x04
#define ARG_KILL_SIGNAL   0x08
#define ARG_MADVISE       0x10
#define ARG_SIGACTION     0x20
#define ARG_SIGPROCMASK   0x40
#define ARG_FORCE_SLOW    0x80
#define ARG_SIGALTSTACK   0x100

/* Syscall table */
extern const int16_t bsd_to_linux[BSD_SYSCALL_MAX];
extern const uint8_t bsd_arg_flags[BSD_SYSCALL_MAX];

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

#endif /* SYSCALL_INTERNAL_H */
#define BACKWARD_SCAN_BYTES 32
