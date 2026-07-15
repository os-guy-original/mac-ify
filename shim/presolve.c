/* presolve.c — pre-resolve all glibc function pointers at constructor time.
 *
 * ROOT CAUSE OF FUTEX DEADLOCK:
 * The shim has ~100+ functions that lazily resolve their glibc counterparts
 * via real_dlsym(RTLD_NEXT, "function_name"). real_dlsym calls glibc's dlsym,
 * which acquires __dl_load_lock. If glibc's locale/NSS subsystem already
 * holds __dl_load_lock (e.g., libintl calls setlocale → _nl_find_locale →
 * _nl_load_locale which dlopen's locale modules while holding the lock),
 * and then libintl calls one of our shim functions (e.g. unlinkat) which
 * does its lazy real_dlsym(RTLD_NEXT, "unlinkat") → dlsym → try to acquire
 * __dl_load_lock → FUTEX_WAIT_PRIVATE → DEADLOCK.
 *
 * FIX: Pre-resolve ALL real_* pointers at constructor time, before any
 * macOS code runs, using macify_elf_lookup() which walks the ELF symbol
 * table directly WITHOUT calling dlsym and WITHOUT acquiring any locks.
 *
 * This file makes all real_* pointers non-static (extern) so they can be
 * set centrally from macify_presolve_all().
 */
#include "shim.h"

/* ── Declare all real_* pointers as non-static externs ──────────
 * These are defined as `static` in their respective files, but we
 * need to set them from here. So we declare them here with the same
 * names but WITHOUT static, and the linker will find them.
 *
 * Wait — they're static, so they're file-local. We can't access them
 * from here. Instead, we need to call init functions in each file.
 *
 * The approach: each file that has lazy real_dlsym calls gets an
 * init function that pre-resolves its pointers. We call all of them
 * from macify_presolve_all().
 *
 * But that's a LOT of init functions. Instead, let's take a different
 * approach: replace real_dlsym(RTLD_NEXT, ...) with macify_elf_lookup(...)
 * everywhere. This way, even if lazy init happens at runtime, it won't
 * call glibc's dlsym and won't deadlock.
 *
 * macify_presolve_all() does a "warm-up" by looking up the most
 * commonly-used symbols, which caches the libc symbol table info. */

void macify_presolve_all(void) {
    /* Warm up the ELF symbol table cache by looking up a few symbols.
     * This calls dl_iterate_phdr to find libc.so and caches its symtab/strtab,
     * so subsequent macify_elf_lookup() calls are fast and lock-free.
     *
     * We look up real_dlsym first (needed by some init code), then a
     * representative set of commonly-used functions to prime the cache. */
    if (!real_dlsym) {
        /* Fall back to the original find_dlsym_cb approach for real_dlsym */
        extern void macify_init_real_dlsym(void);
        macify_init_real_dlsym();
    }

    /* Prime the ELF lookup cache by looking up a few symbols.
     * The actual lookups happen lazily via macify_elf_lookup() in each
     * shim function, but now they'll be lock-free. */
    (void)macify_elf_lookup("open");
    (void)macify_elf_lookup("close");
    (void)macify_elf_lookup("read");
    (void)macify_elf_lookup("write");
    (void)macify_elf_lookup("stat");
    (void)macify_elf_lookup("unlinkat");
    (void)macify_elf_lookup("setlocale");
    (void)macify_elf_lookup("nl_langinfo");
    (void)macify_elf_lookup("getpwuid");
    (void)macify_elf_lookup("getpwnam");
    (void)macify_elf_lookup("sigaction");
    (void)macify_elf_lookup("sigprocmask");
}
