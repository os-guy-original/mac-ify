#include "pthread_internal.h"


/* macOS pthread extensions. */

/* The loader allocates an 8MB stack for the macOS binary and switches to
 * it before calling main(). But glibc's pthread_getattr_np for the main
 * thread still returns the KERNEL's stack info (from /proc/self/maps),
 * not our allocated stack. Rust's runtime uses pthread_get_stackaddr_np
 * to find the main thread's stack, computes guard page addresses from it,
 * and crashes when those don't match the actual stack pointer.
 *
 * Fix: the loader calls __macify_set_stack_info() with our allocated
 * stack base/size. pthread_get_stack*_np returns these values for the
 * main thread instead of querying glibc. */
void *macify_main_stack_base = NULL;
size_t macify_main_stack_size = 0;
static pthread_t macify_main_thread_id = {0};
static int macify_main_thread_id_set = 0;

void __macify_set_stack_info(void *base, size_t size) {
    macify_main_stack_base = base;
    macify_main_stack_size = size;
    /* Record the main thread's pthread_t so we can identify it later. */
    if (!macify_main_thread_id_set) {
        macify_main_thread_id = pthread_self();
        macify_main_thread_id_set = 1;
    }
}

/* Returns 1 if the current thread is the main thread, 0 otherwise. */
int is_main_thread(void) {
    if (!macify_main_thread_id_set) return 0;
    return pthread_equal(pthread_self(), macify_main_thread_id);
}

void *pthread_get_stackaddr_np(pthread_t thread) {
    /* For the main thread, return our allocated stack top. For other
     * threads, query glibc. We detect the main thread by comparing
     * thread to the recorded main thread ID. */
    if (macify_main_stack_base && pthread_equal(thread, macify_main_thread_id)) {
        return (char *)macify_main_stack_base + macify_main_stack_size;
    }
    pthread_attr_t attr;
    void *stackaddr = NULL;
    size_t stacksize = 0;
    pthread_getattr_np(thread, &attr);
    pthread_attr_getstack(&attr, &stackaddr, &stacksize);
    pthread_attr_destroy(&attr);
    return (char *)stackaddr + stacksize;  /* top of stack */
}

size_t pthread_get_stacksize_np(pthread_t thread) {
    if (macify_main_stack_base && pthread_equal(thread, macify_main_thread_id)) {
        if (getenv("MACIFY_TRACE_PTHREAD")) {
            char b[160]; int n = snprintf(b, sizeof(b), "macify: pthread_get_stacksize_np(thread=%lu main=%lu) -> %zu (main thread)\n", (unsigned long)thread, (unsigned long)macify_main_thread_id, macify_main_stack_size);
            (void)write(2, b, n);
        }
        return macify_main_stack_size;
    }
    pthread_attr_t attr;
    size_t stacksize = 0;
    pthread_getattr_np(thread, &attr);
    pthread_attr_getstacksize(&attr, &stacksize);
    pthread_attr_destroy(&attr);
    if (getenv("MACIFY_TRACE_PTHREAD")) {
        char b[160]; int n = snprintf(b, sizeof(b), "macify: pthread_get_stacksize_np(thread=%lu) -> %zu (non-main)\n", (unsigned long)thread, stacksize);
        (void)write(2, b, n);
    }
    return stacksize;
}
