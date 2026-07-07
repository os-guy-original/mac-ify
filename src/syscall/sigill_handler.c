/* sigill_handler.c — SIGILL slow-path handler for syscall translation */
#include "syscall_internal.h"

/* Buffers for sigprocmask syscall translation (macOS 4-byte ↔ Linux 8-byte sigset_t).
 * Thread-local to avoid races when signals are delivered concurrently on
 * multiple threads. */
static __thread unsigned char linux_set_sigprocmask[8];
static __thread unsigned char linux_oset_sigprocmask[8];

/* Buffers for sigaltstack syscall translation (macOS/Linux stack_t field order differs). */
#include <signal.h>
static __thread stack_t linux_ss_sigaltstack;
static __thread stack_t linux_oss_sigaltstack;

/* Pre-resolved shim symbols — looked up once at init, NOT inside the
 * signal handler (dlsym is not async-signal-safe). */
static void *(*macify_go_signal_wrapper_ptr)(int, siginfo_t *, void *) = NULL;
static void **macify_saved_go_handlers_ptr = NULL;
static int shim_symbols_resolved = 0;

/* Called from main.c after shim is loaded — pre-resolves symbols
 * so the SIGILL handler doesn't need to call dlsym. */
void sigill_handler_pre_resolve(void) {
    if (!shim_symbols_resolved) {
        macify_go_signal_wrapper_ptr = dlsym(RTLD_DEFAULT, "macify_go_signal_wrapper");
        macify_saved_go_handlers_ptr = dlsym(RTLD_DEFAULT, "macify_saved_go_handlers");
        shim_symbols_resolved = 1;
    }
}

void sigill_handler(int sig, siginfo_t *info, void *uctx) {
    (void)sig; (void)info;
    ucontext_t *uc = (ucontext_t *)uctx;
    greg_t *regs = uc->uc_mcontext.gregs;

    uint64_t macos_nr = (uint64_t)regs[REG_RAX];
    uint32_t bsd_nr   = macos_nr & 0xFFFFFF;

    /* Debug: count SIGILL handler invocations */
    g_slow_path_calls++;
    if (getenv("MACIFY_TRACE_SIGILL") || (g_verbose && g_slow_path_calls <= 5)) {
        fprintf(stderr, "macify: SIGILL #%lu: bsd_nr=%u (rax=0x%llx)\n",
                g_slow_path_calls, bsd_nr, (unsigned long long)macos_nr);
    }

    /* Fast bounds check. Most syscalls are < 600. */
    if (__builtin_expect(bsd_nr >= BSD_SYSCALL_MAX, 0)) {
        fprintf(stderr,
                "\nmacify: unhandled macOS syscall 0x%llx (BSD #%u, out of range)\n",
                (unsigned long long)macos_nr, bsd_nr);
        _exit(127);
    }

    int16_t linux_nr = bsd_to_linux[bsd_nr];
    if (__builtin_expect(linux_nr <= 0, 0)) {
        /* linux_nr == 0 means "unimplemented" (unused table slot). */
        fprintf(stderr,
                "\nmacify: unhandled macOS syscall 0x%llx (BSD #%u = %s)\n",
                (unsigned long long)macos_nr, bsd_nr, bsd_syscall_name(bsd_nr));
        _exit(127);
    }

    uint8_t flags = bsd_arg_flags[bsd_nr];

    /* For exit (BSD 1): print stats, then exit_group. */
    if (__builtin_expect(bsd_nr == 1, 0)) {
        if (g_verbose) {
            fprintf(stderr, "macify: syscall exit(code=%lld)\n",
                    (long long)regs[REG_RDI]);
        }
        print_stats();
        raw_syscall(SYS_exit_group, regs[REG_RDI], 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }

    /* Extract args. */
    long a1 = regs[REG_RDI];
    long a2 = regs[REG_RSI];
    /* For sigprocmask: save original macOS oset pointer for post-syscall copy */
    void *sigprocmask_save_macos_oset = NULL;
    /* For sigaltstack: save original macOS oss pointer for post-syscall copy */
    void *sigaltstack_save_macos_oss = NULL;
    long a3 = regs[REG_RDX];
    long a4 = regs[REG_R10];
    long a5 = regs[REG_R8];
    long a6 = regs[REG_R9];

    /* Per-syscall argument translation. */
    if (flags & ARG_OPEN_FLAGS) {
        int old_a2 = (int)a2;
        a2 = (long)translate_open_flags(old_a2);
        if (g_verbose) {
            fprintf(stderr, "macify:   open flags macos=%#x -> linux=%#lx\n",
                    (unsigned)old_a2, a2);
        }
    }
    if (flags & ARG_MMAP_FLAGS) {
        int old_a4 = (int)a4;
        a4 = (long)translate_mmap_flags(old_a4);
        if (g_verbose) {
            fprintf(stderr, "macify:   mmap flags macos=%#x -> linux=%#lx\n",
                    (unsigned)old_a4, a4);
        }
    }
    if (flags & ARG_KILL_SIGNAL) {
        int old_a2 = (int)a2;
        a2 = (long)translate_kill_signal(old_a2);
        if (g_verbose) {
            fprintf(stderr, "macify:   kill signal macos=%d -> linux=%ld\n",
                    old_a2, a2);
        }
    }
    if (flags & ARG_FCNTL_CMD) {
        int old_a2 = (int)a2;
        int new_a2 = translate_fcntl_cmd(old_a2);
        if (new_a2 < 0) {
            /* macOS-specific cmd with no Linux equivalent. Return EINVAL. */
            if (g_verbose) {
                fprintf(stderr, "macify:   fcntl cmd macos=%d -> UNSUPPORTED\n",
                        old_a2);
            }
            regs[REG_RAX] = (greg_t)(-EINVAL);
            regs[REG_RIP] += 2;
            return;
        }
        a2 = (long)new_a2;
        if (g_verbose) {
            fprintf(stderr, "macify:   fcntl cmd macos=%d -> linux=%ld\n",
                    old_a2, a2);
        }
    }
    if (flags & ARG_MADVISE) {
        int old_a3 = (int)a3;
        a3 = (long)translate_madvise(old_a3);
        if (g_verbose) {
            fprintf(stderr, "macify:   madvise advice macos=%d -> linux=%ld\n",
                    old_a3, a3);
        }
    }
    if (flags & ARG_SIGACTION) {
        /* macOS sigaction(int signum, const struct sigaction *act,
         *                  struct sigaction *oldact)
         * a1 = signum, a2 = act (macOS struct ptr), a3 = oldact (macOS struct ptr)
         * Translate signal number from macOS to Linux (they differ!).
         */
        if (a1 == 4 /*SIGILL*/ || a1 == 11 /*SIGSEGV*/ || a1 == 10 /*SIGBUS*/) {
            /* NEVER let the macOS binary replace our SIGILL/SIGSEGV/SIGBUS
             * handlers. SIGILL is critical for syscall translation.
             * SIGSEGV/SIGBUS are our crash handlers. */
            if (g_verbose) {
                fprintf(stderr, "macify:   sigaction(%ld) - skipped, keeping our handler\n", a1);
            }
            regs[REG_RAX] = 0;  /* return success */
            regs[REG_RIP] += 2;  /* skip UD2 */
            return;
        }
        if (a2) {
            static struct {
                void *handler;
                unsigned long flags;
                void *restorer;
                unsigned char mask[128];
            } linux_sa;
            uint8_t *macos_sa = (uint8_t *)a2;
            memset(&linux_sa, 0, sizeof(linux_sa));
            unsigned int macos_flags = *(unsigned int *)(macos_sa + 12);
            void *go_handler = *(void **)macos_sa;

            /* For Go binaries: install the signal deferral wrapper instead
             * of Go's handler directly. This prevents signals from being
             * delivered before m.gsignal is allocated. */
            if (g_tls_g_addr) {
                /* Use pre-resolved shim symbols (no dlsym in signal handler) */
                if (macify_go_signal_wrapper_ptr && macify_saved_go_handlers_ptr) {
                    int linux_sig_for_handler = translate_kill_signal((int)a1);
                    if (linux_sig_for_handler > 0 && linux_sig_for_handler < 32) {
                        macify_saved_go_handlers_ptr[linux_sig_for_handler] = go_handler;
                    }
                    linux_sa.handler = macify_go_signal_wrapper_ptr;
                    linux_sa.flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
                } else {
                    /* Fallback: install Go's handler directly */
                    linux_sa.handler = go_handler;
                    linux_sa.flags = macos_flags | SA_ONSTACK;
                }
            } else {
                linux_sa.handler = go_handler;
                linux_sa.flags = macos_flags | SA_ONSTACK;
            }
            /* Translate the 4-byte macOS sigset mask to 128-byte Linux sigset,
             * translating signal numbers (macOS SIGURG=16 → Linux SIGURG=23, etc.) */
            uint32_t macos_mask = *(uint32_t *)(macos_sa + 8);
            sigset_t linux_mask;
            sigemptyset(&linux_mask);
            for (int ms = 1; ms <= 31; ms++) {
                if (macos_mask & (1u << (ms - 1))) {
                    int ls = translate_kill_signal(ms);
                    if (ls > 0) sigaddset(&linux_mask, ls);
                }
            }
            memcpy(&linux_sa.mask, &linux_mask, sizeof(linux_mask));
            a2 = (long)&linux_sa;
            int macos_signum = (int)a1;
            int linux_signum = translate_kill_signal(macos_signum);
            if (g_verbose) {
                fprintf(stderr, "macify:   sigaction signum macos=%d -> linux=%d handler=%p flags=0x%x -> 0x%lx\n",
                        macos_signum, linux_signum, linux_sa.handler, macos_flags, linux_sa.flags);
            }
            a1 = linux_signum;
        }
        if (a3) {
            static unsigned char linux_old_sa[152];
            a3 = (long)linux_old_sa;
        }
    }
    if (flags & ARG_SIGPROCMASK) {
        sigprocmask_save_macos_oset = (void *)a3;
        if (a2) {
            /* Translate 4-byte macOS sigset to 8-byte Linux sigset,
             * translating signal numbers (macOS SIGURG=16 → Linux SIGURG=23).
             * Just copying the bitmask would block the WRONG signals! */
            uint32_t macos_mask = *(uint32_t *)a2;
            uint64_t linux_mask = 0;
            for (int ms = 1; ms <= 31; ms++) {
                if (macos_mask & (1u << (ms - 1))) {
                    int ls = translate_kill_signal(ms);
                    if (ls > 0 && ls < 64) {
                        linux_mask |= (1ULL << (ls - 1));
                    }
                }
            }
            /* Never allow blocking SIGSEGV(11) or SIGABRT(6) — our crash
             * recovery handler must always be able to run. */
            if (a1 == 1 /* SIG_BLOCK */ || a1 == 3 /* SIG_SETMASK */) {
                linux_mask &= ~(1ULL << 10);  /* SIGSEGV = bit 10 */
                linux_mask &= ~(1ULL << 5);   /* SIGABRT = bit 5 */
            }
            *(uint64_t *)linux_set_sigprocmask = linux_mask;
            a2 = (long)linux_set_sigprocmask;
        }
        if (a3) {
            a3 = (long)linux_oset_sigprocmask;
        }
        a4 = 8;  /* sigsetsize = sizeof(kernel_sigset_t) = 8 */
        if (g_verbose) {
            fprintf(stderr, "macify:   sigprocmask how=%ld set=%p oset=%p sigsetsize=8\n",
                    a1, (void *)a2, (void *)a3);
        }
    }
    if (flags & ARG_SIGALTSTACK) {
        sigaltstack_save_macos_oss = (void *)a2;
        if (a1) {
            uint8_t *macos_ss = (uint8_t *)a1;
            memset(&linux_ss_sigaltstack, 0, sizeof(linux_ss_sigaltstack));
            linux_ss_sigaltstack.ss_sp = *(void **)macos_ss;
            linux_ss_sigaltstack.ss_flags = *(int *)(macos_ss + 16);
            linux_ss_sigaltstack.ss_size = *(size_t *)(macos_ss + 8);

            /* NEVER allow disabling the signal stack — our crash handler
             * requires SA_ONSTACK to work. Replace SS_DISABLE with our own. */
            if (linux_ss_sigaltstack.ss_flags & 0x1 /* SS_DISABLE */) {
                static char fallback_sigstack[1024 * 1024] __attribute__((aligned(4096)));
                linux_ss_sigaltstack.ss_sp = fallback_sigstack;
                linux_ss_sigaltstack.ss_size = sizeof(fallback_sigstack);
                linux_ss_sigaltstack.ss_flags = 0;
            }
            /* Also block SS_ONSTACK — macOS code shouldn't set this */
            linux_ss_sigaltstack.ss_flags &= ~0x2;
            a1 = (long)&linux_ss_sigaltstack;
        }
        if (a2) {
            a2 = (long)&linux_oss_sigaltstack;
        }
    }
    /* wait4 options WCONTINUED bit differs (macOS 0x4 vs Linux 0x8) but is
     * rarely used; left untranslated. */

    if (g_verbose) {
        fprintf(stderr, "macify: syscall %-16s macos=0x%-10llx -> linux=%-3d  "
                        "args=%#llx,%#llx,%#llx,%#llx,%#llx,%#llx\n",
                bsd_syscall_name(bsd_nr),
                (unsigned long long)macos_nr, (int)linux_nr,
                (unsigned long long)a1, (unsigned long long)a2,
                (unsigned long long)a3, (unsigned long long)a4,
                (unsigned long long)a5, (unsigned long long)a6);
    }

    long result = raw_syscall((long)linux_nr, a1, a2, a3, a4, a5, a6);

    /* Linux raw syscalls return -errno on failure (e.g., -9 for EBADF).
     * macOS raw syscalls return -1 on failure and set errno via __errno().
     * Real macOS apps check for -1, not -errno.
     *
     * We convert -errno → -1 and set errno via our shim's __errno() function.
     * The shim's __errno() returns __errno_location(), so errno is properly set. */
    /* Track whether the syscall errored (before converting -errno → -1).
     * Go's asmSyscall6 checks CF: CF=1 means error, CF=0 means success. */
    bool syscall_error = (result < 0 && result > -4096);

    if (__builtin_expect(syscall_error, 0)) {
        /* result is -errno. Set errno and convert to -1 (macOS convention). */
        int err = (int)(-result);
        errno = err;  /* Sets glibc's errno via __errno_location() */
        if (g_verbose) {
            fprintf(stderr, "macify:   syscall failed: linux returned %ld (-errno=%d), "
                            "converting to -1 (macOS convention)\n", result, err);
        }
        result = -1;
    }

    /* Post-syscall: for sigprocmask, translate 8-byte Linux sigset → 4-byte macOS sigset.
     * Must translate signal numbers back (Linux SIGURG=23 → macOS SIGURG=16). */
    if (flags & ARG_SIGPROCMASK) {
        if (sigprocmask_save_macos_oset && result == 0) {
            uint64_t linux_mask = *(uint64_t *)linux_oset_sigprocmask;
            uint32_t macos_mask = 0;
            for (int ls = 1; ls <= 31; ls++) {
                if (linux_mask & (1ULL << (ls - 1))) {
                    /* Find macOS signal that maps to this Linux signal */
                    for (int ms = 1; ms <= 31; ms++) {
                        if (translate_kill_signal(ms) == ls) {
                            macos_mask |= (1u << (ms - 1));
                            break;
                        }
                    }
                }
            }
            *(uint32_t *)sigprocmask_save_macos_oset = macos_mask;
        }
    }
    /* Post-syscall: for sigaltstack, convert Linux stack_t → macOS stack_t */
    if (flags & ARG_SIGALTSTACK) {
        if (sigaltstack_save_macos_oss && result == 0) {
            uint8_t *macos_oss = (uint8_t *)sigaltstack_save_macos_oss;
            *(void **)macos_oss = linux_oss_sigaltstack.ss_sp;           /* offset 0 */
            *(size_t *)(macos_oss + 8) = linux_oss_sigaltstack.ss_size;  /* macOS: size at 8 */
            *(int *)(macos_oss + 16) = linux_oss_sigaltstack.ss_flags;   /* macOS: flags at 16 */
        }
    }

    regs[REG_RAX] = (greg_t)result;

    /* Set carry flag to match macOS syscall convention.
     * macOS: CF=1 on error (errno set), CF=0 on success.
     * Linux: returns -errno on error, non-negative on success.
     * Go's asmSyscall6 checks CF via 'jae' (jump if CF=0 = success).
     * We must set EFLAGS.CF accordingly or Go misinterprets results. */
    if (syscall_error) {
        regs[REG_EFL] |= 0x0001;  /* set CF */
    } else {
        regs[REG_EFL] &= ~0x0001UL;  /* clear CF */
    }

    regs[REG_RIP] += 2;  /* skip past the 2-byte UD2 (0F 0B) */
}



#define BACKWARD_SCAN_BYTES 32

