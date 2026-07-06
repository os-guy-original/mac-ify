/* ucontext.c — macOS ucontext stubs (OpenSSL async API) */
#include "../shim.h"
#include <ucontext.h>

int getcontext(ucontext_t *ucp) {
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: getcontext(%p) -> 0\n", ucp);
        (void)write(2, b, n);
    }
    if (ucp) memset(ucp, 0, sizeof(*ucp));
    return 0;
}

int setcontext(const ucontext_t *ucp) {
    (void)ucp;
    errno = ENOSYS;
    return -1;
}

void makecontext(ucontext_t *ucp, void (*func)(void), int argc, ...) {
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: makecontext(%p, %p, %d)\n", ucp, (void*)func, argc);
        (void)write(2, b, n);
    }
    (void)ucp; (void)func; (void)argc;
}

int swapcontext(ucontext_t *oucp, const ucontext_t *ucp) {
    if (getenv("MACIFY_SSL_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "SSL_DEBUG: swapcontext(%p, %p) -> 0\n", oucp, ucp);
        (void)write(2, b, n);
    }
    (void)oucp; (void)ucp;
    return 0;
}
