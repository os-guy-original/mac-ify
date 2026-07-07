/* sigset.c — sigaddset/sigdelset/sigemptyset/sigfillset/sigismember overrides
 * macOS sigset_t = 4 bytes, Linux = 128 bytes */
#include "signal_internal.h"
#include <signal.h>

/* sigaddset/sigemptyset/sigfillset: macOS sigset_t = 4 bytes, Linux = 128.
 *
 * CRITICAL: These functions are called by BOTH macOS code (4-byte sigset)
 * AND glibc internal code (128-byte sigset). Due to symbol interposition,
 * glibc's internal calls to sigemptyset/sigaddset get OUR overrides.
 *
 * If we only write 4 bytes when glibc expects 128, the remaining 124 bytes
 * contain stack garbage, causing glibc to see random signals as blocked.
 * This corrupts glibc's internal signal handling and causes data corruption.
 *
 * Solution: check the caller. If macOS code, use 4-byte sigset. If glibc,
 * delegate to glibc's real version (found via real_dlsym). */
int sigaddset(sigset_t *set, int signum) {
    
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        /* macOS caller: 4-byte sigset */
        uint32_t *mask = (uint32_t *)set;
        *mask |= (1u << (signum - 1));
        return 0;
    }
    /* glibc caller: 128-byte sigset — set bit directly */
    unsigned long *bits = (unsigned long *)set;
    if (signum > 0 && signum <= 64) bits[0] |= (1UL << (signum - 1));
    return 0;
}

int sigdelset(sigset_t *set, int signum) {
    
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        uint32_t *mask = (uint32_t *)set;
        *mask &= ~(1u << (signum - 1));
        return 0;
    }
    /* glibc caller: 128-byte sigset — clear bit directly */
    unsigned long *bits = (unsigned long *)set;
    if (signum > 0 && signum <= 64) bits[0] &= ~(1UL << (signum - 1));
    return 0;
}

int sigemptyset(sigset_t *set) {
    
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        *(uint32_t *)set = 0;
        return 0;
    }
    /* glibc caller: zero the full 128-byte sigset */
    memset(set, 0, sizeof(sigset_t));
    return 0;
}

int sigfillset(sigset_t *set) {
    
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        *(uint32_t *)set = 0xFFFFFFFF;
        return 0;
    }
    /* glibc caller: fill the full 128-byte sigset */
    memset(set, 0xff, sizeof(sigset_t));
    return 0;
}

int sigismember(const sigset_t *set, int signum) {
    
    if (macify_caller_is_macos_text(__builtin_return_address(0))) {
        uint32_t mask = *(const uint32_t *)set;
        return (mask & (1u << (signum - 1))) ? 1 : 0;
    }
    /* glibc caller: check 128-byte sigset */
    const unsigned long *bits = (const unsigned long *)set;
    if (signum > 0 && signum <= 64) return (bits[0] & (1UL << (signum - 1))) ? 1 : 0;
    return 0;
}
