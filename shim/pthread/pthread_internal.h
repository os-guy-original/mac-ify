/* pthread_internal.h — shared declarations for shim/pthread/ */
#ifndef PTHREAD_INTERNAL_H
#define PTHREAD_INTERNAL_H

#include "../shim.h"
#include <signal.h>
#include <sys/syscall.h>
#include <pthread.h>

/* ── Constants ── */
#define MACIFY_MAX_KEYS 256

#define MACOS_PTHREAD_MUTEX_SIG  0x32AAABA7u
#define MACOS_PTHREAD_COND_SIG   0x3CB0B5BBu
#define MACOS_PTHREAD_RWLOCK_SIG 0x2DA8B3B4u
#define MACOS_PTHREAD_ATTR_SIG   0x54485244u

#define MACOS_CLOCK_MONOTONIC             6
#define MACOS_CLOCK_PROCESS_CPUTIME_ID   12
#define MACOS_CLOCK_THREAD_CPUTIME_ID    16
#define MACOS_CLOCK_UPTIME_RAW           8
#define MACOS_CLOCK_MONOTONIC_RAW        4

/* ── Stack info (stack.c) ── */
extern void *macify_main_stack_base;
extern size_t macify_main_stack_size;
int is_main_thread(void);

/* ── Sync function pointers (sync.c — defines them, others use them) ── */
extern int   (*real_mutex_lock)(pthread_mutex_t *);
extern int   (*real_mutex_trylock)(pthread_mutex_t *);
extern int   (*real_mutex_unlock)(pthread_mutex_t *);
extern int   (*real_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
extern int   (*real_mutex_destroy)(pthread_mutex_t *);
extern int   (*real_cond_wait)(pthread_cond_t *, pthread_mutex_t *);
extern int   (*real_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
extern int   (*real_cond_signal)(pthread_cond_t *);
extern int   (*real_cond_broadcast)(pthread_cond_t *);
extern int   (*real_cond_init)(pthread_cond_t *, const pthread_condattr_t *);
extern int   (*real_cond_destroy)(pthread_cond_t *);
extern int   (*real_rwlock_rdlock)(pthread_rwlock_t *);
extern int   (*real_rwlock_wrlock)(pthread_rwlock_t *);
extern int   (*real_rwlock_unlock)(pthread_rwlock_t *);
extern int   (*real_rwlock_init)(pthread_rwlock_t *, const pthread_rwlockattr_t *);
extern int   (*real_rwlock_destroy)(pthread_rwlock_t *);

void init_real_pthread_funcs(void);
void convert_macos_mutex(pthread_mutex_t *m);
void convert_macos_cond(pthread_cond_t *c);
void convert_macos_rwlock(pthread_rwlock_t *rw);
pthread_cond_t *get_glibc_cond(pthread_cond_t *c);

/* ── TLS (tls.c) ── */
extern pthread_mutex_t macify_tls_mutex;

/* ── Attr function pointers (attr.c) ── */
extern int (*real_attr_init)(pthread_attr_t *);
extern int (*real_attr_destroy)(pthread_attr_t *);
extern int (*real_attr_setstacksize)(pthread_attr_t *, size_t);
extern int (*real_attr_getstacksize)(const pthread_attr_t *, size_t *);
extern int (*real_attr_setguardsize)(pthread_attr_t *, size_t);

/* ── Create (create.c) ── */
extern int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                   void *(*)(void *), void *);

/* ── Signal translation (from shim/signal/) ── */
int macos_sig_to_linux_signal(int macos_sig);

/* ── macos_pthread_attr (already in shim.h, but need sig check) ── */

#endif /* PTHREAD_INTERNAL_H */

/* ── OpenSSL ret globals (used by tls.c and create.c) ── */
struct ret_global_entry { const char *name; uint64_t static_addr; };
extern const struct ret_global_entry ret_global_entries[];

/* ── SSL hooks (ssl_hooks.c) ── */
void macify_print_ret_globals(void);
void macify_force_ssl_init_success(void);
void *macify_ossl_lib_ctx_hook(void);
extern uint64_t macify_image_header;
