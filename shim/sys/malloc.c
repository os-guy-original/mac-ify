#include <malloc.h>
/* Split from misc.c */
#include "../shim.h"

void malloc_set_zone_name(void *zone, const char *name) { (void)zone; (void)name; }
size_t malloc_size(const void *ptr) {
    if (!ptr) return 0;
    size_t r = malloc_usable_size((void *)ptr);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "macify: malloc_size(%p) -> %zu\n", ptr, r);
        (void)write(2, b, n);
    }
    return r;
}
void *malloc_zone_malloc(void *zone, size_t size) {
    void *r = malloc(size);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[160];
        int n = snprintf(b, sizeof(b), "macify: malloc_zone_malloc(zone=%p, %zu) -> %p\n", zone, size, r);
        (void)write(2, b, n);
    }
    return r;
}
void *malloc_zone_realloc(void *zone, void *ptr, size_t size) {
    void *r = realloc(ptr, size);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[160];
        int n = snprintf(b, sizeof(b), "macify: malloc_zone_realloc(zone=%p, %p, %zu) -> %p\n", zone, (void *)1, size, r);
        (void)write(2, b, n);
    }
    return r;
}
void malloc_zone_free(void *zone, void *ptr) {
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[128];
        int n = snprintf(b, sizeof(b), "macify: malloc_zone_free(zone=%p, %p)\n", zone, ptr);
        (void)write(2, b, n);
    }
    free(ptr);
}
void *malloc_zone_calloc(void *zone, size_t n, size_t size) {
    void *r = calloc(n, size);
    if (getenv("MACIFY_MALLOC_DEBUG")) {
        char b[160];
        int m = snprintf(b, sizeof(b), "macify: malloc_zone_calloc(zone=%p, %zu, %zu) -> %p\n", zone, n, size, r);
        (void)write(2, b, m);
    }
    return r;
}
void *malloc_zone_memalign(void *zone, size_t align, size_t size) {
    void *r = NULL;
    (void)zone;
    posix_memalign(&r, align, size);
    return r;
}
#include <malloc.h>
