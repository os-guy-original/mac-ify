/* unwind.c — C++ exception handling via libgcc_s forwarding */
#include "../shim.h"

struct _Unwind_Exception;
struct _Unwind_Context;
typedef int (*_Unwind_Stop_Fn)(int, struct _Unwind_Exception *, struct _Unwind_Context *);

static void *libgcc_s_handle;

static void *libgcc_fn(const char *name) {
    if (!libgcc_s_handle) {
        libgcc_s_handle = dlopen("libgcc_s.so.1", RTLD_LAZY | RTLD_GLOBAL);
        if (!libgcc_s_handle) libgcc_s_handle = dlopen("libgcc_s.so.2", RTLD_LAZY | RTLD_GLOBAL);
    }
    return libgcc_s_handle ? dlsym(libgcc_s_handle, name) : NULL;
}

#define UNWIND_FORWARD(name, ret, args, ...) \
    ret name args { \
        ret (*fn) args = libgcc_fn(#name); \
        if (fn) return fn(__VA_ARGS__); \
        return (ret)0; \
    }

#define UNWIND_FORWARD_VOID(name, args, ...) \
    void name args { \
        void (*fn) args = libgcc_fn(#name); \
        if (fn) fn(__VA_ARGS__); \
    }

int _Unwind_Backtrace(_Unwind_Stop_Fn stop, void *stop_arg) {
    int (*fn)(_Unwind_Stop_Fn, void *) = libgcc_fn("_Unwind_Backtrace");
    return fn ? fn(stop, stop_arg) : 5;
}
UNWIND_FORWARD_VOID(_Unwind_DeleteException, (struct _Unwind_Exception *exc), exc)
UNWIND_FORWARD(_Unwind_GetIP, unsigned long, (struct _Unwind_Context *ctx), ctx)
UNWIND_FORWARD(_Unwind_GetIPInfo, unsigned long, (struct _Unwind_Context *ctx, int *ip), ctx, ip)
UNWIND_FORWARD(_Unwind_GetLanguageSpecificData, void *, (struct _Unwind_Context *ctx), ctx)
UNWIND_FORWARD(_Unwind_GetRegionStart, unsigned long, (struct _Unwind_Context *ctx), ctx)
UNWIND_FORWARD_VOID(_Unwind_SetGR, (struct _Unwind_Context *ctx, int i, unsigned long v), ctx, i, v)
UNWIND_FORWARD_VOID(_Unwind_SetIP, (struct _Unwind_Context *ctx, unsigned long v), ctx, v)
UNWIND_FORWARD(_Unwind_RaiseException, int, (struct _Unwind_Exception *exc), exc)
UNWIND_FORWARD_VOID(_Unwind_Resume, (struct _Unwind_Exception *exc), exc)
UNWIND_FORWARD(_Unwind_GetGR, unsigned long, (struct _Unwind_Context *ctx, int i), ctx, i)
UNWIND_FORWARD(_Unwind_GetCFA, unsigned long, (struct _Unwind_Context *ctx), ctx)
UNWIND_FORWARD(_Unwind_GetDataRelBase, void *, (struct _Unwind_Context *ctx), ctx)
UNWIND_FORWARD(_Unwind_GetTextRelBase, void *, (struct _Unwind_Context *ctx), ctx)
