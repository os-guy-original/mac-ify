# Darwin userspace libc ground truth

Headers fetched from apple-oss-distributions (main branches) for the
macOS *userspace* ABI — struct layouts and constants that guest
binaries were compiled against.

## Files

| File | Source | What it settles |
|---|---|---|
| `pthread_impl.h` | libpthread `include/pthread/pthread_impl.h` | Static-initializer signatures: `_PTHREAD_MUTEX_SIG_init=0x32AAABA7`, `_PTHREAD_RECURSIVE_MUTEX_SIG_init=0x32AAABA2`, `_PTHREAD_ERRORCHECK_MUTEX_SIG_init=0x32AAABA1`, `_PTHREAD_FIRSTFIT_MUTEX_SIG_init=0x32AAABA3`, `_PTHREAD_COND_SIG_init=0x3CB0B1BB`, `_PTHREAD_ONCE_SIG_init=0x30B1BCBA`, `_PTHREAD_RWLOCK_SIG_init=0x2DA8B3B4` |
| `_pthread_{cond,mutex,rwlock}_t.h`, `_pthread_types.h` | libpthread `include/sys/_pthread/` | Opaque object sizes and the `__darwin_pthread_*` typedef shapes |
| `pthread.h` | libpthread `include/pthread/pthread.h` | Public constants (initializers, attributes, prims) |
| `_stdio.h` | Libc `include/_stdio.h` | The real Darwin `__sFILE` layout on LP64: `_p@0x00 _r@0x08 _w@0x0c _flags@0x10(2B) _file@0x12(2B) _bf{base@0x18,size@0x20} _lbfsize@0x28 … _offset@0x88` — note `_bf` at **0x18/0x20**, not the 0x14/0x1c claimed by macos_stdio.c comments (fix before building the macos_sFILE facade) |
| `floatio.h` | Libc `stdio/FreeBSD/floatio.h` | stdio internals used by the BSD implementation (EOF handling etc.) |
| `netdb.h` | macOS SDK `usr/include/netdb.h`, mirror `phracker/MacOSX-SDKs` (`MacOSX11.3.sdk`) | `struct addrinfo` field order: `ai_flags@0 ai_family@4 ai_socktype@8 ai_protocol@12 ai_addrlen@16 ai_canonname@24 ai_addr@32 ai_next@40` — `ai_canonname` precedes `ai_addr`, the reverse of glibc's `ai_addr@24 ai_canonname@32`; `socklen_t` is 4 bytes on both, so only the two pointer fields swap |

The shim's pthread signature constants in
`shim/pthread/pthread_internal.h` are verified character-for-character
against `pthread_impl.h` as fetched. Any future change to mutex/cond/
rwlock conversion must cite that file, and any change to stdio
facade plans must cite `_stdio.h` — layout claims from memory are how
the 0x14/0x1c error got into the codebase.
