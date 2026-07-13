/* signal_internal.h — internal declarations for shim/signal/ */
#ifndef SHIM_SIGNAL_INTERNAL_H
#define SHIM_SIGNAL_INTERNAL_H

#include "../shim.h"

/* Cached glibc signal restorer function — needed for SA_RESTORER flag. */
extern void (*macify_sa_restorer)(void);

/* Our own signal restorer function — calls rt_sigreturn syscall. */
void macify_restore_rt(void);

/* Crash handler that prints info and exits. */
void macify_crash_handler(int sig, siginfo_t *info, void *uctx);

/* Go signal wrapper and state */
extern void *macify_saved_go_handlers[32];
extern void macify_go_signal_wrapper(int sig, siginfo_t *info, void *uctx);

/* Signal number translation */
int macos_sig_to_linux_signal(int macos_sig);

/* macOS → Linux signal number translation (internal). */
int macos_sig_to_linux(int macos_sig);
int linux_sig_to_macos(int linux_sig);

/* Sigset conversion */
void macos_to_linux_sigset(const void *macos_set, sigset_t *linux_set);
void linux_to_macos_sigset(const sigset_t *linux_set, void *macos_set);

/* atfork support */
int is_forked_child(void);

/* SIGCHLD wrapper — defers signal during terminal reads to prevent
 * readline crash. */
extern void (*macify_saved_sigchld_handler)(int, siginfo_t *, void *);
extern volatile int macify_in_terminal_read;
void macify_sigchld_wrapper(int sig, siginfo_t *info, void *uctx);

/* Function declarations for macify_get_shim_symbol */
sighandler_t macify_signal(int signum, sighandler_t handler) __asm__("signal");
int macify_sigaltstack(const void *ss, void *oss) __asm__("sigaltstack");
int macify_pthread_sigmask(int how, const void *set, void *oldset) __asm__("pthread_sigmask");
int macify_sigprocmask(int how, const void *set, void *oldset) __asm__("sigprocmask");

#endif /* SHIM_SIGNAL_INTERNAL_H */
