/* iokit.c — IOKit framework stubs for htop */
#include "../shim.h"

/* ── IOKit stubs for htop ───────────────────────────────────────
 * htop uses IOKit for power source info (battery). We stub these. */

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
