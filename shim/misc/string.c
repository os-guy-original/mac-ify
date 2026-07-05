/* string.c — BSD string functions and fortified variants */
#include "../shim.h"

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

static void ensure_libgcc(void) {
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

