/* dl.c — dynamic linking overrides: dlopen, dlsym, dlclose, and
 * SystemConfiguration / CoreFoundation stubs used by c-ares. */
#include "io_internal.h"

#define MACOS_RTLD_DEFAULT ((void *)-2)
#define MACOS_RTLD_SELF    ((void *)-3)
#define MACOS_RTLD_MAIN_ONLY ((void *)-5)

static void *macify_sc_fake_handle = (void *)&macify_sc_fake_handle;

void *macify_SCDynamicStoreCreate(void *alloc, const void *name, void *cb, void *ctx);
void *macify_SCDynamicStoreCopyValue(void *store, const void *key);
void macify_CFRelease(void *cf);
void *macify_CFStringCreateWithCString(void *alloc, const char *cstr, unsigned int encoding);
int macify_CFStringGetCString(const void *cfstr, char *buf, long buf_size, unsigned int encoding);
long macify_CFStringGetLength(const void *cfstr);
long macify_CFStringGetMaximumSizeForEncoding(long length, unsigned int encoding);
long CFArrayGetCount(const void *arr);
const void *CFArrayGetValueAtIndex(const void *arr, long idx);
const void *CFDictionaryGetValue(const void *dict, const void *key);
void *macify_dns_configuration_copy(void);
void macify_dns_configuration_free(void *config);

void *(*real_dlsym)(void *, const char *);

static int find_dlsym_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libc.so"))
        return 0;
    void **pp = (void **)data;
    pp[0] = (void *)info->dlpi_addr;
    return 1;
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
    if (!real_dlsym) {
        void *libc_base = NULL;
        dl_iterate_phdr(find_dlsym_callback, &libc_base);
        if (libc_base) {
            real_dlsym = (void *(*)(void *, const char *))
                ((char *)libc_base + ((char *)dlsym - (char *)NULL));
        }
        if (!real_dlsym) real_dlsym = dlsym(RTLD_DEFAULT, "dlsym");
    }
    if (handle == MACOS_RTLD_DEFAULT || handle == MACOS_RTLD_SELF) {
        handle = NULL;
    }
    if (handle == macify_sc_fake_handle) {
        if (strcmp(symbol, "SCDynamicStoreCreate") == 0)
            return (void *)macify_SCDynamicStoreCreate;
        else if (strcmp(symbol, "SCDynamicStoreCopyValue") == 0)
            return (void *)macify_SCDynamicStoreCopyValue;
        else if (strcmp(symbol, "CFRelease") == 0)
            return (void *)macify_CFRelease;
        else if (strcmp(symbol, "CFStringCreateWithCString") == 0)
            return (void *)macify_CFStringCreateWithCString;
        else if (strcmp(symbol, "CFStringGetCString") == 0)
            return (void *)macify_CFStringGetCString;
        else if (strcmp(symbol, "CFStringGetLength") == 0)
            return (void *)macify_CFStringGetLength;
        else if (strcmp(symbol, "CFStringGetMaximumSizeForEncoding") == 0)
            return (void *)macify_CFStringGetMaximumSizeForEncoding;
        else if (strcmp(symbol, "CFArrayGetCount") == 0)
            return (void *)CFArrayGetCount;
        else if (strcmp(symbol, "CFArrayGetValueAtIndex") == 0)
            return (void *)CFArrayGetValueAtIndex;
        else if (strcmp(symbol, "CFDictionaryGetValue") == 0)
            return (void *)CFDictionaryGetValue;
        else if (strcmp(symbol, "dns_configuration_copy") == 0)
            return (void *)macify_dns_configuration_copy;
        else if (strcmp(symbol, "dns_configuration_free") == 0)
            return (void *)macify_dns_configuration_free;
        return NULL;
    }
    return real_dlsym(handle, symbol);
}

int dlclose(void *handle) {
    if (handle == macify_sc_fake_handle) return 0;
    static int (*real_dlclose)(void *) = NULL;
    if (!real_dlclose) real_dlclose = dlsym(RTLD_DEFAULT, "dlclose");
    return real_dlclose(handle);
}
