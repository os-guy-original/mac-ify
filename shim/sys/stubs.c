/* Split from misc.c */
#include "../shim.h"

/* misc.c — remaining macOS compatibility stubs */
#include "../shim.h"
#include <sys/mount.h>
#include <ucontext.h>
#include <stdarg.h>
#include <malloc.h>

/* ── libgcc_s loading for _Unwind_* functions ────────────────── */

static void *libgcc_s_handle = NULL;

static void __attribute__((unused)) ensure_libgcc(void) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (!libgcc_s_handle)
            libgcc_s_handle = dlopen("libgcc_s.so.2", RTLD_NOW | RTLD_GLOBAL);
    }
}

/* dyld_stub_binder — macOS lazy binding handler. Mac-ify resolves all lazy
 * binds eagerly at load time, so this should never be called. If it is, a
 * lazy symbol wasn't resolved — return 0 (NULL/no-op) so the binary can
 * continue running instead of crashing. This is safer than abort(). */

void dyld_stub_binder(void) {
    /* Return 0 — the calling stub expects a function address.
     * The binary will get a NULL function pointer and likely crash
     * when it tries to call it, but at least we get further. */
    if (getenv("MACIFY_VERBOSE"))
        fprintf(stderr, "macify: dyld_stub_binder called — unresolved lazy symbol\n");
    __asm__ volatile("xor %rax, %rax; ret");
}

/* ___chkstk_darwin — stack probe function.
 * 
 * macOS calls this before large stack allocations to touch each page
 * and trigger guard page exceptions. On Linux, stack growth is handled
 * automatically by the kernel, so this is a no-op.
 * 
 * The argument is the stack size in bytes. The function must not be
 * optimized away — it's called with a specific stack layout.
 */

__attribute__((noinline))
void ___chkstk_darwin(unsigned long size) {
    (void)size;
    /* No-op on Linux — the kernel handles stack growth automatically. */
    __asm__ volatile("" ::: "memory");
}

/* Also provide __chkstk_darwin (two underscores) for completeness */
__attribute__((noinline))
void __chkstk_darwin(unsigned long size) {
    (void)size;
    __asm__ volatile("" ::: "memory");
}

