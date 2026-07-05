/* unwind.c — C++ exception handling via libgcc_s forwarding */
#include "../shim.h"

struct _Unwind_Exception;
struct _Unwind_Context;
typedef int (*_Unwind_Stop_Fn)(int, struct _Unwind_Exception *, struct _Unwind_Context *);

static void *libgcc_s_handle;

static void *libgcc_fn(const char *name) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (!libgcc_s_handle) libgcc_s_handle = dlopen("libgcc_s.so.2", RTLD_NOW | RTLD_GLOBAL);
    }
    return libgcc_s_handle ? dlsym(libgcc_s_handle, name) : NULL;
}

int _Unwind_Backtrace(_Unwind_Stop_Fn stop, void *stop_arg) {
    int (*fn)(_Unwind_Stop_Fn, void *) = libgcc_fn("_Unwind_Backtrace");
    return fn ? fn(stop, stop_arg) : 5;
}

void _Unwind_DeleteException(struct _Unwind_Exception *exc) {
    void (*fn)(struct _Unwind_Exception *) = libgcc_fn("_Unwind_DeleteException");
    if (fn) fn(exc);
}

unsigned long _Unwind_GetIP(struct _Unwind_Context *ctx) {
    unsigned long (*fn)(struct _Unwind_Context *) = libgcc_fn("_Unwind_GetIP");
    return fn ? fn(ctx) : 0;
}

unsigned long _Unwind_GetIPInfo(struct _Unwind_Context *ctx, int *ip_before_insn) {
    unsigned long (*fn)(struct _Unwind_Context *, int *) = libgcc_fn("_Unwind_GetIPInfo");
    if (fn) return fn(ctx, ip_before_insn);
    if (ip_before_insn) *ip_before_insn = 0;
    return 0;
}

void *_Unwind_GetLanguageSpecificData(struct _Unwind_Context *ctx) {
    void *(*fn)(struct _Unwind_Context *) = libgcc_fn("_Unwind_GetLanguageSpecificData");
    return fn ? fn(ctx) : NULL;
}

unsigned long _Unwind_GetRegionStart(struct _Unwind_Context *ctx) {
    unsigned long (*fn)(struct _Unwind_Context *) = libgcc_fn("_Unwind_GetRegionStart");
    return fn ? fn(ctx) : 0;
}

void _Unwind_SetGR(struct _Unwind_Context *ctx, int index, unsigned long val) {
    void (*fn)(struct _Unwind_Context *, int, unsigned long) = libgcc_fn("_Unwind_SetGR");
    if (fn) fn(ctx, index, val);
}

void _Unwind_SetIP(struct _Unwind_Context *ctx, unsigned long val) {
    void (*fn)(struct _Unwind_Context *, unsigned long) = libgcc_fn("_Unwind_SetIP");
    if (fn) fn(ctx, val);
}

int _Unwind_RaiseException(struct _Unwind_Exception *exc) {
    int (*fn)(struct _Unwind_Exception *) = libgcc_fn("_Unwind_RaiseException");
    return fn ? fn(exc) : 3; /* _URC_FATAL_PHASE1_ERROR */
}

void _Unwind_Resume(struct _Unwind_Exception *exc) {
    void (*fn)(struct _Unwind_Exception *) = libgcc_fn("_Unwind_Resume");
    if (fn) fn(exc);
    abort(); /* must not return */
}

unsigned long _Unwind_GetGR(struct _Unwind_Context *ctx, int index) {
    unsigned long (*fn)(struct _Unwind_Context *, int) = libgcc_fn("_Unwind_GetGR");
    return fn ? fn(ctx, index) : 0;
}

unsigned long _Unwind_GetCFA(struct _Unwind_Context *ctx) {
    unsigned long (*fn)(struct _Unwind_Context *) = libgcc_fn("_Unwind_GetCFA");
    return fn ? fn(ctx) : 0;
}

void *_Unwind_GetDataRelBase(struct _Unwind_Context *ctx) {
    void *(*fn)(struct _Unwind_Context *) = libgcc_fn("_Unwind_GetDataRelBase");
    return fn ? fn(ctx) : NULL;
}

void *_Unwind_GetTextRelBase(struct _Unwind_Context *ctx) {
    void *(*fn)(struct _Unwind_Context *) = libgcc_fn("_Unwind_GetTextRelBase");
    return fn ? fn(ctx) : NULL;
}
