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

/* Find glibc's real dlsym by walking libc.so's ELF dynamic symbol table.
 * We can't use dlsym(RTLD_NEXT, "dlsym") because that would recurse. */
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

void *dlopen(const char *filename, int flag) {
    if (filename && strstr(filename, "SystemConfiguration")) {
        return macify_sc_fake_handle;
    }
    static void *(*real_dlopen)(const char *, int) = NULL;
    if (!real_dlopen) real_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    return real_dlopen(filename, flag);
}

void *dlsym(void *handle, const char *symbol) {
    /* Intercept dlsym for our fake SystemConfiguration handle. */
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
    /* Find real glibc dlsym on first call */
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
