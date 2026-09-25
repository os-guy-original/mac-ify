/* string.c — BSD string functions and fortified variants */
#include "../shim.h"

/* ── qsort_r / qsort_b: Darwin ABI adapters ──────────────────────────
 * GROUND TRUTH (Apple libc): macOS qsort_r is BSD-style:
 *     void qsort_r(void *base, size_t nel, size_t width,
 *                  void *thunk,
 *                  int (*compar)(void *thunk, const void *a, const void *b));
 * glibc's qsort_r is a DIFFERENT argument order and compar shape:
 *     void qsort_r(void *base, size_t nel, size_t width,
 *                  int (*compar)(const void *a, const void *b, void *arg),
 *                  void *arg);
 * A Darwin-built guest's compar pointer lands in glibc's `arg` slot and
 * glibc's arg lands in the guest's `thunk` slot; glibc then CALLS the
 * guest's compar with (a, b, thunk) — i.e. with the thunk as its FIRST
 * argument. Observed: rubygems boot SIGSEGVs inside glibc qsort_r
 * (gdb backtrace frames 7-9: qsort_r called from guest text) while
 * sorting during `require "rubygems"` — the trampoline jumps to a
 * bogus address derived from the thunk. This breaks EVERY Darwin
 * binary that sorts with a context, not just ruby. */
struct macify_qsort_r_ctx {
    void *thunk;
    int (*compar)(void *, const void *, const void *);
};

static int macify_qsort_r_cmp(const void *a, const void *b, void *arg) {
    struct macify_qsort_r_ctx *ctx = (struct macify_qsort_r_ctx *)arg;
    return ctx->compar(ctx->thunk, a, b);
}

void macify_qsort_r(void *base, size_t nel, size_t width, void *thunk,
                    int (*compar)(void *, const void *, const void *))
        __asm__("qsort_r");
void macify_qsort_r(void *base, size_t nel, size_t width, void *thunk,
                    int (*compar)(void *, const void *, const void *)) {
    struct macify_qsort_r_ctx ctx = { thunk, compar };
    qsort_r(base, nel, width, macify_qsort_r_cmp, &ctx);
}

/* macOS qsort_b takes a block (compare function with no separate thunk);
 * glibc has no equivalent. Map it onto qsort with the block as the
 * comparator — signature-compatible (both take two const void*). */
void macify_qsort_b(void *base, size_t nel, size_t width,
                    int (*compar)(const void *, const void *))
        __asm__("qsort_b");
void macify_qsort_b(void *base, size_t nel, size_t width,
                    int (*compar)(const void *, const void *)) {
    qsort(base, nel, width, compar);
}

/* _memset_pattern16 — macOS-specific memset with 16-byte pattern. */

void memset_pattern16(void *dst, const void *pattern, size_t len) {
    const uint8_t *p = (const uint8_t *)pattern;
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < len; i += 16) {
        size_t chunk = (len - i < 16) ? (len - i) : 16;
        for (size_t j = 0; j < chunk; j++) {
            d[i + j] = p[j];
        }
    }
}
#include <dlfcn.h>

static void *libgcc_s_handle = NULL;

static void __attribute__((unused)) ensure_libgcc(void) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (!libgcc_s_handle) {
            libgcc_s_handle = dlopen("libgcc_s.so", RTLD_NOW | RTLD_GLOBAL);
        }
    }
}


/* strlcpy / strlcat — BSD string functions not in older glibc.
 * macOS uses these extensively; glibc added them only in 2.38+. */
size_t strlcpy(char *dst, const char *src, size_t siz) {
    size_t len = strlen(src);
    if (siz > 0) {
        size_t copy = len < siz ? len : siz - 1;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return len;
}

size_t strlcat(char *dst, const char *src, size_t siz) {
    size_t dlen = strlen(dst);
    size_t slen = strlen(src);
    if (dlen >= siz) return slen + siz;
    size_t copy = (slen < siz - dlen) ? slen : siz - dlen - 1;
    memcpy(dst + dlen, src, copy);
    dst[dlen + copy] = '\0';
    return dlen + slen;
}

/* Fortified variants — just call the base functions */
size_t __strlcpy_chk(char *dst, const char *src, size_t siz, size_t dstlen) {
    (void)dstlen;
    return strlcpy(dst, src, siz);
}
size_t __strlcat_chk(char *dst, const char *src, size_t siz, size_t dstlen) {
    (void)dstlen;
    return strlcat(dst, src, siz);
}

