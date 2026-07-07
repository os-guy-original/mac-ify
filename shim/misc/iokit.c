/* iokit.c — IOKit framework stubs for htop */
#include "../shim.h"

/* ── IOKit stubs for htop ───────────────────────────────────────
 * htop uses IOKit for power source info (battery). We stub these.
 * dust (Rust disk-usage tool) also uses IOKit to enumerate disk
 * statistics via IORegistryEntryGetName + IORegistryEntryCreateCFProperty. */

/* kIOMasterPortDefault — deprecated alias for kIOMainPortDefault.
 * Many binaries still reference this. Both should be 0 (the default
 * master port). */
void *kIOMasterPortDefault = (void *)0;
void *kIOMainPortDefault = (void *)0;

void *IOServiceMatching(const char *name) {
    (void)name;
    return NULL;
}

void *IOServiceGetMatchingService(void *mainPort, void *matching) {
    (void)mainPort; (void)matching;
    return NULL;
}

int IOServiceGetMatchingServices(void *mainPort, void *matching, void *existing) {
    (void)mainPort; (void)matching; (void)existing;
    return 0;  /* kIOReturnSuccess but no iterators */
}

int IOIteratorNext(void *iterator) {
    (void)iterator;
    return 0;  /* no more objects */
}

void IOObjectRelease(void *obj) {
    (void)obj;
}

int IORegistryEntryCreateCFProperties(void *entry, void *props, void *alloc, unsigned int options) {
    (void)entry; (void)props; (void)alloc; (void)options;
    return 0;
}

void *IORegistryEntryCreateCFProperty(void *entry, void *key, void *alloc, unsigned int options) {
    (void)entry; (void)key; (void)alloc; (void)options;
    return NULL;
}

/* IORegistryEntryGetName — get the name of an IORegistry entry.
 * macOS signature: kern_return_t IORegistryEntryGetName(io_registry_entry_t entry, io_name_t name);
 * io_name_t is a 128-byte char buffer. We return kIOReturnNotFound (no entry)
 * and fill the buffer with an empty string so callers don't read garbage. */
int IORegistryEntryGetName(void *entry, char *name) {
    (void)entry;
    if (name) {
        name[0] = '\0';
    }
    return 0;  /* kIOReturnSuccess but empty name */
}

/* IORegistryEntryGetPath — get the path of an IORegistry entry.
 * Returns kIOReturnNotFound and fills the buffer with empty string. */
int IORegistryEntryGetPath(void *entry, const char *plane, char *path) {
    (void)entry; (void)plane;
    if (path) path[0] = '\0';
    return 0;
}

/* IOObjectGetClass — get the class name of an IO object. */
int IOObjectGetClass(void *obj, char *className) {
    (void)obj;
    if (className) className[0] = '\0';
    return 0;
}

/* IOObjectConformsTo — check if an IO object conforms to a class. Returns 0 (false). */
int IOObjectConformsTo(void *obj, const char *className) {
    (void)obj; (void)className;
    return 0;
}

/* IORegistryEntryGetParentEntry — get the parent entry. Returns 0 (no parent). */
int IORegistryEntryGetParentEntry(void *entry, const char *plane, void *parent) {
    (void)entry; (void)plane;
    if (parent) *(void **)parent = NULL;
    return 0;
}

/* IORegistryEntryGetChildEntry — get a child entry. Returns 0 (no child). */
int IORegistryEntryGetChildEntry(void *entry, const char *plane, void *child) {
    (void)entry; (void)plane;
    if (child) *(void **)child = NULL;
    return 0;
}

/* IOKit power source stubs */
void *IOPSCopyPowerSourcesInfo(void) {
    return NULL;
}

void *IOPSCopyPowerSourcesList(void *blob) {
    (void)blob;
    return NULL;  /* empty array */
}

void *IOPSGetPowerSourceDescription(void *blob, void *ps) {
    (void)blob; (void)ps;
    return NULL;
}

/* Additional IOKit stubs for btm (bottom) */
int IOConnectCallStructMethod(void *connection, unsigned int selector,
    const void *inputStruct, size_t inputStructCnt,
    void *outputStruct, size_t *outputStructCnt) {
    (void)connection; (void)selector; (void)inputStruct; (void)inputStructCnt;
    (void)outputStruct; (void)outputStructCnt;
    return 0xe00002c2;
}

int IOServiceClose(void *service) {
    (void)service;
    return 0;
}

int IOServiceOpen(void *service, void *owningTask, unsigned int type, void **connection) {
    (void)service; (void)owningTask; (void)type;
    if (connection) *connection = NULL;
    return 0xe00002c2;
}
