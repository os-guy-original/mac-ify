/* dl.c — dynamic linking overrides: dlopen, dlsym, dlclose, and
 * SystemConfiguration / CoreFoundation stubs used by c-ares. */
#include "io_internal.h"

#define MACOS_RTLD_DEFAULT ((void *)-2)
#define MACOS_RTLD_SELF    ((void *)-3)

static void *macify_sc_fake_handle = (void *)&macify_sc_fake_handle;

/* Define real_dlsym (declared extern in shim.h) */
void *(*real_dlsym)(void *, const char *);

/* Forward declarations (defined in cf.c) */
void *macify_SCDynamicStoreCreate(void *alloc, const void *name, void *cb, void *ctx);
void *macify_SCDynamicStoreCopyValue(void *store, const void *key);
void macify_CFRelease(void *cf);
void *CFStringCreateWithCString(void *alloc, const char *cstr, unsigned int encoding);
int CFStringGetCString(const void *cfstr, char *buf, long buf_size, unsigned int encoding);
long CFStringGetLength(const void *cfstr);
long CFStringGetMaximumSizeForEncoding(long length, unsigned int encoding);
long CFArrayGetCount(const void *arr);
const void *CFArrayGetValueAtIndex(const void *arr, long idx);
const void *CFDictionaryGetValue(const void *dict, const void *key);
void *macify_dns_configuration_copy(void);
void macify_dns_configuration_free(void *config);

/* Forward declaration */
static int find_dlsym_cb(struct dl_phdr_info *info, size_t size, void *data);

/* Initialize real_dlsym by walking libc.so's ELF dynamic symbol table.
 * This MUST be called early (in the constructor) because:
 * 1. The dlsym override might not be called (glibc's dlsym is found first
 *    in the symbol search order when the shim is loaded as a dependency)
 * 2. Other shim functions (sigaction, signal, etc.) call real_dlsym directly
 * 3. If real_dlsym is NULL when called, the call jumps to 0, crashing */
void macify_init_real_dlsym(void) {
    if (!real_dlsym) {
        dl_iterate_phdr(find_dlsym_cb, &real_dlsym);
    }
}

/* Find glibc's real dlsym by walking libc.so's ELF dynamic symbol table.
 * We can't use real_dlsym(RTLD_NEXT, "dlsym") because that would recurse. */
static int find_dlsym_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libc.so"))
        return 0;
    ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;
    ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    uint32_t *hash = NULL;
    for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB) symtab = (ElfW(Sym) *)d->d_un.d_ptr;
        else if (d->d_tag == DT_STRTAB) strtab = (const char *)d->d_un.d_ptr;
        else if (d->d_tag == DT_HASH) hash = (uint32_t *)d->d_un.d_ptr;
    }
    if (!symtab || !strtab) return 0;
    /* Use DT_HASH to get symbol count (nchain = hash[1]) */
    int nsyms = hash ? (int)hash[1] : 4096; /* fallback limit */
    for (int i = 0; i < nsyms; i++) {
        ElfW(Sym) *s = &symtab[i];
        const char *name = strtab + s->st_name;
        if (!name[0]) continue;
        if (strcmp(name, "dlsym") == 0 && s->st_value) {
            *((void **)data) = (void *)(info->dlpi_addr + s->st_value);
            return 1;
        }
    }
    return 0;
}

/* ── macify_elf_lookup ──────────────────────────────────────────
 * Lock-free ELF symbol lookup. Walks libc.so's (and ld-linux's) dynamic
 * symbol table directly, WITHOUT calling glibc's dlsym.
 *
 * WHY: glibc's dlsym acquires __dl_load_lock. If glibc's NSS or locale
 * subsystem already holds that lock (e.g., during libintl's setlocale
 * → _nl_find_locale → _nl_load_locale), and our shim function does a
 * lazy real_dlsym(RTLD_NEXT, "unlinkat"), dlsym tries to acquire
 * __dl_load_lock → FUTEX_WAIT_PRIVATE → DEADLOCK.
 *
 * This function walks the ELF tables directly — no locks needed.
 * It searches libc.so.6 first, then ld-linux, then libm, then libpthread
 * (for older glibc where pthread functions are separate).
 *
 * The lookup is cached: once we find a symbol, we cache the dlpi_addr
 * of the library that contained it, so subsequent lookups in the same
 * library are faster. */
static void *g_elf_libc_base = NULL;  /* cached dlpi_addr of libc.so */
static ElfW(Sym) *g_elf_libc_symtab = NULL;
static const char *g_elf_libc_strtab = NULL;
static int g_elf_libc_nsyms = 0;

/* Callback to find libc.so and cache its symbol table info. */
static int find_libc_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libc.so"))
        return 0;
    ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;
    ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    uint32_t *hash = NULL;
    for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB) symtab = (ElfW(Sym) *)d->d_un.d_ptr;
        else if (d->d_tag == DT_STRTAB) strtab = (const char *)d->d_un.d_ptr;
        else if (d->d_tag == DT_HASH) hash = (uint32_t *)d->d_un.d_ptr;
        else if (d->d_tag == DT_GNU_HASH) hash = (uint32_t *)d->d_un.d_ptr; /* GNU hash as fallback */
    }
    if (!symtab || !strtab) return 0;
    int nsyms = 0;
    if (hash) {
        /* DT_HASH: hash[0]=nbucket, hash[1]=nchain */
        nsyms = (int)hash[1];
    }
    if (nsyms <= 0) nsyms = 65536; /* fallback for GNU_HASH-only libs */
    g_elf_libc_base = (void *)info->dlpi_addr;
    g_elf_libc_symtab = symtab;
    g_elf_libc_strtab = strtab;
    g_elf_libc_nsyms = nsyms;
    return 1;
}

/* Look up a symbol by name in libc.so's ELF dynamic symbol table.
 * Returns the function address, or NULL if not found.
 * NO LOCKS — walks the read-only ELF tables directly.
 *
 * If the symbol is not found in libc's ELF table (e.g., it's a private
 * glibc symbol like __xstat or __clone), falls back to real_dlsym(RTLD_NEXT).
 * This fallback COULD deadlock, but only for rare symbols — the common
 * case (open, read, write, stat, unlinkat, etc.) is resolved lock-free. */
void *macify_elf_lookup(const char *name) {
    if (!g_elf_libc_symtab) {
        dl_iterate_phdr(find_libc_cb, NULL);
    }
    if (g_elf_libc_symtab && g_elf_libc_strtab) {
        for (int i = 0; i < g_elf_libc_nsyms; i++) {
            ElfW(Sym) *s = &g_elf_libc_symtab[i];
            if (!s->st_value) continue;
            const char *symname = g_elf_libc_strtab + s->st_name;
            if (!symname[0]) continue;
            if (strcmp(symname, name) == 0) {
                return (void *)((uintptr_t)g_elf_libc_base + s->st_value);
            }
        }
    }
    /* Fallback: use real_dlsym for symbols not in libc's dynamic symbol table.
     * This handles versioned/private symbols like __xstat, __select, __clone.
     * WARNING: This can deadlock if __dl_load_lock is held. But these symbols
     * are typically only called outside of locale/NSS init, so it's safe. */
    if (real_dlsym) {
        return real_dlsym(RTLD_NEXT, name);
    }
    return NULL;
}

void *dlopen(const char *filename, int flag) {
    if (filename && strstr(filename, "SystemConfiguration")) {
        return macify_sc_fake_handle;
    }
    static void *(*real_dlopen)(const char *, int) = NULL;
    if (!real_dlopen) {
        if (!real_dlsym) dl_iterate_phdr(find_dlsym_cb, &real_dlsym);
        if (real_dlsym) real_dlopen = real_dlsym(RTLD_DEFAULT, "dlopen");
    }
    if (real_dlopen) return real_dlopen(filename, flag);
    return NULL;
}

/* dlsym — DON'T override globally.
 * Overriding dlsym causes futex deadlocks because glibc's NSS
 * subsystem calls dlsym internally. Our override calls real_dlsym
 * which acquires glibc's _dl_load_lock, but NSS already holds it.
 *
 * Instead, bash's GOT entries are resolved by the macify loader's
 * resolve_symbol function, which calls dlsym(shim_handle, ...)
 * directly (bypassing any override) and also checks
 * macify_get_shim_symbol for non-exported overrides.
 *
 * Go binaries that use dlsym to look up C functions are handled
 * via macify_get_shim_symbol in resolve_symbol. */
void *dlsym(void *handle, const char *symbol) {
    /* Only intercept for our fake SystemConfiguration handle. */
    if (handle == macify_sc_fake_handle) {
        if (strcmp(symbol, "SCDynamicStoreCreate") == 0)
            return (void *)macify_SCDynamicStoreCreate;
        if (strcmp(symbol, "SCDynamicStoreCopyValue") == 0)
            return (void *)macify_SCDynamicStoreCopyValue;
        if (strcmp(symbol, "CFRelease") == 0)
            return (void *)macify_CFRelease;
        if (strcmp(symbol, "CFRetain") == 0)
            return (void *)macify_CFRelease;
        if (strcmp(symbol, "CFStringCreateWithCString") == 0)
            return (void *)CFStringCreateWithCString;
        if (strcmp(symbol, "CFStringGetCString") == 0)
            return (void *)CFStringGetCString;
        if (strcmp(symbol, "CFStringGetLength") == 0)
            return (void *)CFStringGetLength;
        if (strcmp(symbol, "CFStringGetMaximumSizeForEncoding") == 0)
            return (void *)CFStringGetMaximumSizeForEncoding;
        if (strcmp(symbol, "CFArrayGetCount") == 0)
            return (void *)CFArrayGetCount;
        if (strcmp(symbol, "CFArrayGetValueAtIndex") == 0)
            return (void *)CFArrayGetValueAtIndex;
        if (strcmp(symbol, "CFDictionaryGetValue") == 0)
            return (void *)CFDictionaryGetValue;
        if (strcmp(symbol, "dns_configuration_copy") == 0)
            return (void *)macify_dns_configuration_copy;
        if (strcmp(symbol, "dns_configuration_free") == 0)
            return (void *)macify_dns_configuration_free;
        return NULL;
    }
    /* For ALL other callers: pass through directly to glibc's dlsym.
     * NO caller check, NO macify_get_shim_symbol lookup, NO overhead.
     * This prevents futex deadlocks in glibc's NSS subsystem. */
    if (!real_dlsym) {
        dl_iterate_phdr(find_dlsym_cb, &real_dlsym);
        if (!real_dlsym) return NULL;
    }
    if (handle == MACOS_RTLD_DEFAULT || handle == MACOS_RTLD_SELF)
        handle = NULL;
    return real_dlsym(handle, symbol);
}

int dlclose(void *handle) {
    if (handle == macify_sc_fake_handle) return 0;
    static int (*real_dlclose)(void *) = NULL;
    if (!real_dlclose) real_dlclose = real_dlsym ? real_dlsym(RTLD_DEFAULT, "dlclose") : NULL;
    if (real_dlclose) return real_dlclose(handle);
    return 0;
}
