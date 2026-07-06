/* Split from misc.c */
#include "../shim.h"

void dispatch_async(void *queue, void *block) {
    (void)queue; (void)block;
    /* No-op for now */
}

void dispatch_sync(void *queue, void *block) {
    (void)queue;
    /* Execute block synchronously — but we don't know the block layout.
     * For now, no-op. */
}

void *dispatch_get_main_queue(void) {
    static char main_queue_placeholder;
    return &main_queue_placeholder;
}

void dispatch_release(void *object) {
    (void)object;
}

void *dispatch_retain(void *object) {
    return object;
}

/* dispatch_semaphore stubs — Rust uses these for synchronization.
 * We provide minimal working implementations using POSIX semaphores. */
#include <semaphore.h>

void *dispatch_semaphore_create(long value) {
    sem_t *sem = malloc(sizeof(sem_t));
    if (sem) sem_init(sem, 0, (unsigned)value);
    return sem;
}

long dispatch_semaphore_signal(void *sem) {
    if (sem) sem_post((sem_t *)sem);
    return 0;
}

long dispatch_semaphore_wait(void *sem, void *timeout) {
    (void)timeout;  /* ignore timeout for now */
    if (sem) {
        while (sem_wait((sem_t *)sem) == -1 && errno == EINTR) continue;
    }
    return 0;
}

unsigned long dispatch_time(unsigned long when, long delta) {
    (void)when; (void)delta;
    return 0;  /* 0 = DISPATCH_TIME_NOW */
}


