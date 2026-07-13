/* go_signal.c — Go signal deferral wrapper */
#include "signal_internal.h"
#include <signal.h>

/* ── Go signal deferral wrapper ────────────────────────────────
 * Go's signal handler (sigtrampgo) crashes if a signal arrives before
 * m.gsignal is allocated. We wrap Go's handler and defer signal delivery
 * until Go is ready.
 *
 * "Go ready" is detected by checking if g_tls_g_addr is non-NULL AND
 * the value at *g_tls_g_addr is non-NULL (meaning Go has written &g0
 * to tls_g during rt0_go). After that point, Go's runtime has set up
 * gsignal and can handle signals safely. */

/* Saved Go signal handlers (indexed by Linux signal number). */
void *macify_saved_go_handlers[32] = {0};

static volatile int macify_go_signal_ready = 0;

/* Called by the wrapper to check if Go is ready for signals. */
static int go_is_ready(void) {
    if (macify_go_signal_ready) return 1;
    /* Check if Go has written to tls_g (meaning rt0_go has run)
     * AND m.gsignal is allocated (meaning signal handler can run safely).
     * Go 1.24 m struct: m+0x00=g0, m+0x48=gsignal */
    extern uint64_t g_tls_g_addr;
    if (g_tls_g_addr) {
        uint64_t g = *(volatile uint64_t *)g_tls_g_addr;
        if (g != 0) {
            /* g.m is at g+0x30 */
            uint64_t m = *(volatile uint64_t *)(g + 0x30);
            if (m != 0) {
                /* m.gsignal is at m+0x48 */
                uint64_t gsignal = *(volatile uint64_t *)(m + 0x48);
                if (gsignal != 0) {
                    macify_go_signal_ready = 1;
                    return 1;
                }
            }
        }
    }
    return 0;
}

void macify_go_signal_wrapper(int sig, siginfo_t *info, void *uctx) {
    if (getenv("MACIFY_TRACE_SIGNAL")) {
        char b[256]; int n = snprintf(b, sizeof(b), "macify: go_signal_wrapper(sig=%d) go_ready=%d handler=%p\n",
                sig, macify_go_signal_ready,
                (sig >= 0 && sig < 32) ? macify_saved_go_handlers[sig] : NULL);
        (void)write(2, b, n);
    }
    /* Do NOT restore GS base here — the kernel already preserves GS base
     * during signal delivery (we use arch_prctl, not wrgsbase, so the
     * kernel shadow is correct). Calling arch_prctl inside the signal
     * handler can cause issues on kernel 5.10. */

    if (go_is_ready()) {
        /* Go is ready — call the saved Go handler */
        if (sig >= 0 && sig < 32 && macify_saved_go_handlers[sig]) {
            void (*go_handler)(int, siginfo_t *, void *) =
                (void (*)(int, siginfo_t *, void *))macify_saved_go_handlers[sig];
            if (getenv("MACIFY_TRACE_SIGNAL")) {
                char b[128]; int n = snprintf(b, sizeof(b),
                    "macify: calling Go handler sig=%d fn=%p\n", sig, go_handler);
                (void)write(2, b, n);
            }
            go_handler(sig, info, uctx);
            return;
        }
    } else {
        if (getenv("MACIFY_TRACE_SIGNAL")) {
            char b[128]; int n = snprintf(b, sizeof(b),
                "macify: Go NOT ready, deferring sig=%d\n", sig);
            (void)write(2, b, n);
        }
    }
    /* Go is NOT ready — defer the signal by re-blocking it.
     * The signal will be re-delivered when Go unblocks it via sigprocmask.
     * CRITICAL: use the real glibc sigset_t (128 bytes), not the 4-byte
     * macOS sigset. Our sigemptyset/sigaddset overrides write only 4 bytes,
     * leaving 124 bytes uninitialized — glibc reads all 128 bytes. */
    sigset_t mask;
    /* Manually zero the entire 128-byte sigset, then set the bit */
    memset(&mask, 0, sizeof(mask));
    /* Use the real glibc sigaddset, not our override (which writes only 4 bytes) */
    static int (*real_sigaddset_glibc)(sigset_t *, int) = NULL;
    if (!real_sigaddset_glibc) real_sigaddset_glibc = real_dlsym(RTLD_NEXT, "sigaddset");
    if (real_sigaddset_glibc) {
        real_sigaddset_glibc(&mask, sig);
    } else {
        /* Fallback: set bit manually using glibc's bit layout (sig - 1) */
        unsigned long *bits = (unsigned long *)&mask;
        bits[(sig - 1) / (sizeof(unsigned long) * 8)] |= (1UL << ((sig - 1) % (sizeof(unsigned long) * 8)));
    }
    /* Call glibc's sigprocmask directly (bypass our override which might
     * mistranslate when called from the shim). */
    static int (*real_sigprocmask_glibc)(int, const sigset_t *, sigset_t *) = NULL;
    if (!real_sigprocmask_glibc) real_sigprocmask_glibc = real_dlsym(RTLD_NEXT, "sigprocmask");
    if (real_sigprocmask_glibc) {
        real_sigprocmask_glibc(SIG_BLOCK, &mask, NULL);
    }
}
