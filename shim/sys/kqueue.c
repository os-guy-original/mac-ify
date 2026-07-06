/* Split from misc.c */
#include "../shim.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>

int kqueue(void) {
    /* Create an epoll fd as a stand-in for kqueue. */
    int fd = epoll_create1(EPOLL_CLOEXEC);
    if (fd < 0) {
        errno = ENOSYS;
        __asm__ volatile("stc" ::: "cc");  /* set carry flag (error) */
        return -1;
    }
    char b[64]; int n = snprintf(b, sizeof(b), "macify: kqueue() -> %d\n", fd);
    (void)write(2, b, n);
    errno = 0;  /* clear errno on success */
    __asm__ volatile("clc" ::: "cc");  /* clear carry flag (success) */
    return fd;
}

int kevent(int kq, const void *changelist, int nchanges,
           void *eventlist, int nevents,
           const void *timeout) {
    /* Minimal stub: return 0 events.
     * For changelist operations, pretend success (return nchanges).
     * For event retrieval, return 0 events (with a short sleep if timeout). */
    char b[128]; int n = snprintf(b, sizeof(b), "macify: kevent(kq=%d nchanges=%d nevents=%d timeout=%p)\n", kq, nchanges, nevents, timeout);
    (void)write(2, b, n);
    (void)eventlist;
    if (nchanges > 0) {
        /* Pretend all changes were applied successfully.
         * Return 0 (success) — Go's runtime checks if return < 0 for error. */
        (void)changelist;
        errno = 0;  /* clear errno on success */
        __asm__ volatile("clc" ::: "cc");  /* clear carry flag (success) */
        return 0;
    }
    if (nevents > 0) {
        /* No events available. Just return 0 immediately.
         * Don't block — Go's runtime handles the polling loop. */
        (void)timeout;
    }
    (void)kq;
    errno = 0;  /* clear errno on success */
    __asm__ volatile("clc" ::: "cc");  /* clear carry flag (success) */
    return 0;
}
