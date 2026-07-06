/* mlock.c — mlock/munlock overrides (Go locks signal stack pages) */
#include "../shim.h"

int mlock(const void *addr, size_t len) {
    (void)addr; (void)len;
    return 0;
}
int munlock(const void *addr, size_t len) {
    (void)addr; (void)len;
    return 0;
}
int mlockall(int flags) {
    (void)flags;
    return 0;
}
int munlockall(void) {
    return 0;
}
