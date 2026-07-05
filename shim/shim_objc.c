#include "shim.h"

void *objc_msgSend(void *self, void *sel, ...) {
    (void)self; (void)sel;
    return NULL;
}

void objc_msgSendSuper(void) { }
void objc_msgSend_stret(void *stret, void *self, void *sel, ...) {
    (void)stret; (void)self; (void)sel;
}

/* Class lookup stubs */
void *objc_getClass(const char *name) {
    (void)name;
    return NULL;
}

void *objc_getMetaClass(const char *name) {
    (void)name;
    return NULL;
}

void *objc_allocateClassPair(void *superclass, const char *name, size_t extraBytes) {
    (void)superclass; (void)name; (void)extraBytes;
    return NULL;
}

void objc_registerClassPair(void *cls) {
    (void)cls;
}

/* sel_registerName — register a selector. Return the string as the "selector". */
void *sel_registerName(const char *name) {
    return (void *)name;
}

void *sel_getUid(const char *name) {
    return (void *)name;
}

/* objc_setProperty / objc_getProperty — Objective-C property accessors.
 * These are called by synthesized @property getters/setters. */
void *objc_getProperty(void *self, void *sel, long offset, int isAtomic) {
    (void)sel; (void)isAtomic;
    return *(void **)((char *)self + offset);
}

void objc_setProperty(void *self, void *sel, long offset, void *value, int isAtomic, int shouldCopy) {
    (void)sel; (void)isAtomic; (void)shouldCopy;
    *(void **)((char *)self + offset) = value;
}

void objc_copyStruct(void *dest, const void *src, long size, int isAtomic, int hasStrong) {
    (void)isAtomic; (void)hasStrong;
    memmove(dest, src, size);
}
