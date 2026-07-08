#ifndef IO_INTERNAL_H
#define IO_INTERNAL_H

/* Shared declarations for io/ subdirectory modules.
 * These are internal to the shim's I/O layer — not exported. */

#include "../shim.h"
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>     /* fsync, fdatasync */

/* ── Debug helper ─────────────────────────────────────────────── */

extern int macify_net_debug_enabled;
void macify_net_dbg(const char *msg);
void macify_net_dbg_hex(const char *prefix, const void *p, int n);

/* ── Flag translation ────────────────────────────────────────── */

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

unsigned int translate_open_flags(unsigned int macos_flags);
int translate_fcntl_cmd(int cmd);

/* ── Real function pointers ──────────────────────────────────── */

extern void * (*real_mmap)(void *, size_t, int, int, int, off_t);
extern int    (*real_open)(const char *, int, ...);
extern int    (*real_madvise)(void *, size_t, int);
extern int    (*real_fcntl)(int, int, ...);
extern int    (*real_mprotect)(void *, size_t, int);

void init_real_io_funcs(void);

#define LAZY_INIT_IO() do { \
    if (!real_mmap) init_real_io_funcs(); \
} while (0)

/* ── Sockaddr translation ────────────────────────────────────── */

#define MACOS_AF_INET6  30
#define LINUX_AF_INET6  10

/* Translate macOS sockaddr → Linux sockaddr. Returns 1 if it was a macOS
 * sockaddr (and linux_addr is filled), 0 if it was already Linux format.
 * Defined in net.c. */
int macos_to_linux_sockaddr(const void *macos_addr, uint8_t *linux_addr, socklen_t *addrlen);

/* Translate Linux sockaddr → macOS sockaddr (in-place).
 * Defined in net.c (not inline — used across multiple .c files). */
void linux_to_macos_sockaddr(void *addr, socklen_t addrlen);

#endif /* IO_INTERNAL_H */
