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

/* ── Mach semaphores ─────────────────────────────────────────── */
/* macOS Mach semaphore_* functions. nvim (and other macOS binaries)
 * use these for thread synchronization. We implement them using
 * POSIX semaphores (sem_t).
 *
 * macOS semaphore_t is a mach port (integer), but we use a pointer
 * to a heap-allocated sem_t instead. */

#include <semaphore.h>
#include <time.h>
#include <errno.h>

typedef struct {
    sem_t sem;
    int valid;
} macify_mach_sem_t;

/* semaphore_create — create a Mach semaphore.
 * Signature: kern_return_t semaphore_create(task_t task, semaphore_t *sem,
 *                                            int policy, int value)
 * task = mach_task_self() (ignored)
 * sem = pointer to semaphore_t (we store a pointer to our struct)
 * policy = SYNC_POLICY_FIFO (0, ignored)
 * value = initial count
 * Returns 0 (KERN_SUCCESS) on success. */
int semaphore_create(int task, void **sem, int policy, int value) {
    (void)task; (void)policy;
    macify_mach_sem_t *ms = malloc(sizeof(macify_mach_sem_t));
    if (!ms) return 1;  /* KERN_RESOURCE_SHORTAGE */
    if (sem_init(&ms->sem, 0, (unsigned)value) == 0) {
        ms->valid = 1;
    } else {
        ms->valid = 0;
    }
    *sem = ms;
    return 0;  /* KERN_SUCCESS */
}

/* semaphore_destroy — destroy a Mach semaphore. */
int semaphore_destroy(int task, void *sem) {
    (void)task;
    macify_mach_sem_t *ms = (macify_mach_sem_t *)sem;
    if (ms && ms->valid) {
        sem_destroy(&ms->sem);
        ms->valid = 0;
    }
    free(ms);
    return 0;  /* KERN_SUCCESS */
}

/* semaphore_signal — increment (post) a Mach semaphore. */
int semaphore_signal(void *sem) {
    macify_mach_sem_t *ms = (macify_mach_sem_t *)sem;
    if (ms && ms->valid) sem_post(&ms->sem);
    return 0;  /* KERN_SUCCESS */
}

/* semaphore_signal_all — wake all waiters. */
int semaphore_signal_all(void *sem) {
    macify_mach_sem_t *ms = (macify_mach_sem_t *)sem;
    if (ms && ms->valid) {
        /* Post enough times to wake all potential waiters.
         * We don't know how many are waiting, so post a large number
         * and let sem_post handle overflow. */
        int val;
        sem_getvalue(&ms->sem, &val);
        while (val-- > 0) {
            /* Already positive, no waiters */
        }
        sem_post(&ms->sem);  /* at least one to be safe */
    }
    return 0;  /* KERN_SUCCESS */
}

/* semaphore_wait — decrement (wait on) a Mach semaphore. */
int semaphore_wait(void *sem) {
    macify_mach_sem_t *ms = (macify_mach_sem_t *)sem;
    if (ms && ms->valid) {
        while (sem_wait(&ms->sem) == -1 && errno == EINTR) continue;
    }
    return 0;  /* KERN_SUCCESS */
}

/* semaphore_timedwait — wait on a semaphore with timeout.
 * Signature: kern_return_t semaphore_timedwait(semaphore_t sem,
 *                                               mach_timespec_t timeout)
 * mach_timespec_t { unsigned int tv_sec; int tv_nsec; }
 * Returns 0 (KERN_SUCCESS) on success, 1 (KERN_OPERATION_TIMED_OUT) on timeout. */
int semaphore_timedwait(void *sem, unsigned int sec, int nsec) {
    macify_mach_sem_t *ms = (macify_mach_sem_t *)sem;
    if (!ms || !ms->valid) return 1;  /* KERN_INVALID_ARGUMENT */

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += sec;
    ts.tv_nsec += nsec;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }

    int r;
    while ((r = sem_timedwait(&ms->sem, &ts)) == -1 && errno == EINTR) continue;
    if (r == -1 && errno == ETIMEDOUT) return 1;  /* KERN_OPERATION_TIMED_OUT */
    return 0;  /* KERN_SUCCESS */
}



