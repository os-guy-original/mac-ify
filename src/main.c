#include "macify.h"
#include <string.h>

/* Usage & main */

static void usage(const char *prog) {
    fprintf(stderr,
        "Mac-ify — load and run Mach-O x86_64 binaries on Linux\n"
        "\n"
        "Usage: %s [options] <macho-binary> [args...]\n"
        "\n"
        "Options:\n"
        "  -v, --verbose       enable loader diagnostics\n"
        "  -q, --quiet         suppress loader diagnostics (default)\n"
        "      --no-fast-path  disable immediate patching (force SIGILL slow path)\n"
        "  -h, --help          show this help\n"
        "\n", prog);
}

int main(int argc, char **argv, char **envp) {
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-v") == 0 || strcmp(argv[argi], "--verbose") == 0) {
            g_verbose = true;
            argi++;
        } else if (strcmp(argv[argi], "-q") == 0 || strcmp(argv[argi], "--quiet") == 0) {
            g_verbose = false;
            argi++;
        } else if (strcmp(argv[argi], "--no-fast-path") == 0) {
            g_no_fast_path = true;
            argi++;
        } else if (strcmp(argv[argi], "--") == 0) {
            argi++;
            break;
        } else if (strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "macify: unknown option %s\n", argv[argi]);
            usage(argv[0]);
            return 1;
        }
    }
    if (argi >= argc) { usage(argv[0]); return 1; }

    const char *path = argv[argi];
    int app_argc = argc - argi;
    char **app_argv = argv + argi;

    size_t file_size = 0;
    uint8_t *file_data = load_file(path, &file_size);
    if (!file_data) return 1;

    if (file_size < 4) {
        fprintf(stderr, "macify: file too small (%zu bytes)\n", file_size);
        return 1;
    }

    /* Handle fat/universal binaries (FAT_MAGIC = 0xCAFEBABE).
     * Extract the x86_64 slice and adjust file_data/file_size. */
    uint32_t magic_be = *(uint32_t *)file_data;
    if (magic_be == 0xBEBAFECA) {  /* 0xCAFEBABE in little-endian */
        if (file_size < 8) {
            fprintf(stderr, "macify: fat binary too small\n");
            return 1;
        }
        uint32_t nfat = __builtin_bswap32(*(uint32_t *)(file_data + 4));
        for (uint32_t i = 0; i < nfat && i < 16; i++) {
            uint32_t *fat_arch = (uint32_t *)(file_data + 8 + i * 20);
            uint32_t cputype = __builtin_bswap32(fat_arch[0]);
            uint32_t offset  = __builtin_bswap32(fat_arch[2]);
            uint32_t size    = __builtin_bswap32(fat_arch[3]);
            if (cputype == 0x01000007) {  /* CPU_TYPE_X86_64 */
                if (offset + size > file_size) {
                    fprintf(stderr, "macify: fat binary x86_64 slice extends past EOF\n");
                    return 1;
                }
                file_data = file_data + offset;
                file_size = size;
                /* Don't break - continue to find close_stream too */
            }
        }
    }

    if (file_size < sizeof(mach_header_64)) {
        fprintf(stderr, "macify: file too small (%zu bytes) to be Mach-O\n", file_size);
        return 1;
    }
    mach_header_64 *hdr = (mach_header_64 *)file_data;
    if (hdr->magic != MH_MAGIC_64) {
        fprintf(stderr, "macify: not a Mach-O 64-bit binary (magic=%#x)\n", hdr->magic);
        return 1;
    }
    if (hdr->cputype != CPU_TYPE_X86_64) {
        fprintf(stderr, "macify: not an x86_64 Mach-O (cputype=%#x)\n", hdr->cputype);
        return 1;
    }
    if (hdr->filetype != MH_EXECUTE) {
        fprintf(stderr, "macify: not an MH_EXECUTE (filetype=%u)\n", hdr->filetype);
        return 1;
    }

    if (g_verbose) {
        fprintf(stderr, "macify: loaded %s (%zu bytes, %u load commands, flags=%#x%s)\n",
                path, file_size, hdr->ncmds, hdr->flags,
                (hdr->flags & MH_PIE) ? " [PIE]" : "");
        if (g_no_fast_path) {
            fprintf(stderr, "macify: --no-fast-path active (all syscalls via SIGILL)\n");
        }
    }

    /* Install SIGILL handler BEFORE mapping code.
     * SA_ONSTACK is required because Go's runtime checks that all
     * signal handlers use SA_ONSTACK (it needs signals delivered on
     * the signal stack, not on goroutine stacks). Without SA_ONSTACK,
     * Go panics with "non-Go code set up signal handler without
     * SA_ONSTACK flag". */
    /* Allocate a signal stack (required for SA_ONSTACK to work). */
    static char sigstack[1024 * 1024] __attribute__((aligned(4096)));
    stack_t ss;
    ss.ss_sp = sigstack;
    ss.ss_size = sizeof(sigstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigill_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGILL, &sa, NULL) < 0) {
        perror("sigaction SIGILL");
        return 1;
    }

    /* Install crash handler for SIGSEGV/SIGBUS/SIGFPE.
     * Use raw syscall to bypass glibc's sigaction, which might be
     * intercepted by our shim's override (loaded later via dlopen).
     * SA_ONSTACK is required for Go compatibility. */
    struct sigaction crash_sa;
    memset(&crash_sa, 0, sizeof(crash_sa));
    crash_sa.sa_sigaction = crash_handler;
    crash_sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&crash_sa.sa_mask);
    sigaction(SIGSEGV, &crash_sa, NULL);
    sigaction(SIGBUS,  &crash_sa, NULL);
    sigaction(SIGFPE,  &crash_sa, NULL);
    sigaction(SIGABRT, &crash_sa, NULL);
    sigaction(SIGTRAP, &crash_sa, NULL);

    /* ASLR/PIE slide computation.
     *
     * If the MH_PIE flag is set, pre-scan load commands to find the address
     * span of all segments, reserve a random region of that size via
     * mmap(NULL, ...) (the kernel picks a random free address), compute the
     * slide, then free the reservation. Segments are then mapped individually
     * with MAP_FIXED at vmaddr+slide. For non-PIE binaries, slide=0.
     *
     * However, on some systems the static base address (e.g. 0x100000000)
     * may be in use or unavailable. In that case, we fall back to treating
     * a non-PIE binary as if it were PIE (applying a random slide). This
     * works for test binaries that use only relative addressing, but may
     * break binaries with absolute addresses. */
    int pie_failed __attribute__((unused)) = 0;
    if (hdr->flags & MH_PIE) {
        uint64_t min_vmaddr = UINT64_MAX;
        uint64_t max_vmend = 0;
        uint8_t *scan = file_data + sizeof(mach_header_64);
        uint8_t *scan_end = scan + hdr->sizeofcmds;
        for (uint32_t i = 0; i < hdr->ncmds && scan + 8 <= scan_end; i++) {
            uint32_t cmd     = *(uint32_t *)(void *)scan;
            uint32_t cmdsize = *(uint32_t *)(void *)(scan + 4);
            if (cmdsize == 0) break;
            if (cmd == LC_SEGMENT_64) {
                segment_command_64 *seg = (segment_command_64 *)(void *)scan;
                if (strcmp(seg->segname, "__PAGEZERO") != 0 && seg->vmsize > 0) {
                    if (seg->vmaddr < min_vmaddr) min_vmaddr = seg->vmaddr;
                    if (seg->vmaddr + seg->vmsize > max_vmend)
                        max_vmend = seg->vmaddr + seg->vmsize;
                }
            }
            scan += cmdsize;
        }
        if (min_vmaddr != UINT64_MAX && max_vmend > min_vmaddr) {
            uint64_t span = max_vmend - min_vmaddr;
            /* Let the kernel pick a random free region */
            void *base = mmap(NULL, span, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (base != MAP_FAILED) {
                g_slide = (int64_t)(uintptr_t)base - (int64_t)min_vmaddr;
                /* Keep the reservation! Don't munmap. The segments will be
                 * mapped into this reserved region using mprotect+memcpy
                 * (NOT MAP_FIXED, which can overwrite other mappings). */
                if (g_verbose) {
                    fprintf(stderr, "macify: PIE binary — slide=%#lx (static base=%#lx, random base=%#lx, span=%#lx)\n",
                            (unsigned long)g_slide, (unsigned long)min_vmaddr,
                            (unsigned long)(uintptr_t)base, (unsigned long)span);
                }
            }
        }
    }

    /* Non-PIE fallback: if the binary is not PIE (slide=0), try to probe
     * whether the static base address is available. If not, apply a random
     * slide just like PIE. This fixes test binaries on systems where
     * 0x100000000 is unavailable. */
    if (!(hdr->flags & MH_PIE) && g_slide == 0) {
        uint64_t min_vmaddr = UINT64_MAX;
        uint64_t max_vmend = 0;
        uint8_t *scan = file_data + sizeof(mach_header_64);
        uint8_t *scan_end = scan + hdr->sizeofcmds;
        for (uint32_t i = 0; i < hdr->ncmds && scan + 8 <= scan_end; i++) {
            uint32_t cmd     = *(uint32_t *)(void *)scan;
            uint32_t cmdsize = *(uint32_t *)(void *)(scan + 4);
            if (cmdsize == 0) break;
            if (cmd == LC_SEGMENT_64) {
                segment_command_64 *seg = (segment_command_64 *)(void *)scan;
                if (strcmp(seg->segname, "__PAGEZERO") != 0 && seg->vmsize > 0) {
                    if (seg->vmaddr < min_vmaddr) min_vmaddr = seg->vmaddr;
                    if (seg->vmaddr + seg->vmsize > max_vmend)
                        max_vmend = seg->vmaddr + seg->vmsize;
                }
            }
            scan += cmdsize;
        }
        if (min_vmaddr != UINT64_MAX && max_vmend > min_vmaddr) {
            uint64_t span = max_vmend - min_vmaddr;
            /* Try to mmap at the static base address. If it fails, use a
             * random address instead. */
            void *probe = mmap((void *)(uintptr_t)min_vmaddr, span,
                               PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                               -1, 0);
            if (probe == MAP_FAILED) {
                /* Static address unavailable — fall back to random slide */
                void *base = mmap(NULL, span, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (base != MAP_FAILED) {
                    g_slide = (int64_t)(uintptr_t)base - (int64_t)min_vmaddr;
                    /* Keep the reservation — don't munmap */
                    if (g_verbose) {
                        fprintf(stderr, "macify: non-PIE binary — static base unavailable, using slide=%#lx\n",
                                (unsigned long)g_slide);
                    }
                }
            }
            /* If probe succeeded, the reservation is already at the right place.
             * Don't munmap — keep it for mprotect+memcpy. */
        }
    }

    /* Walk load commands. */
    uint8_t *lc = file_data + sizeof(mach_header_64);
    uint8_t *lc_end = lc + hdr->sizeofcmds;
    uint64_t main_entryoff = 0;
    int have_main = 0;

    /* Pre-pass: collect LC_RPATH entries and compute the executable's
     * directory. We need these for resolving @rpath/, @loader_path/, and
     * @executable_path/ in LC_LOAD_DYLIB paths. */
    #define MAX_RPATHS 16
    char *g_rpaths[MAX_RPATHS];
    int g_nrpaths = 0;
    /* Deferred dylibs: @rpath/@loader_path-resolved Mach-O dylibs that
     * need their dependencies loaded first. We load them after the main
     * walk so all @@HOMEBREW_PREFIX@@ dylibs are already registered. */
    #define MAX_DEFERRED_DYLIBS 8
    char g_deferred_dylibs[MAX_DEFERRED_DYLIBS][4096];
    int g_ndeferred_dylibs = 0;
    char exec_dir[4096];
    char exec_abs[4096];
    /* Get the absolute path of the executable */
    if (realpath(path, exec_abs)) {
        /* exec_dir = dirname(exec_abs) */
        strncpy(exec_dir, exec_abs, sizeof(exec_dir) - 1);
        exec_dir[sizeof(exec_dir) - 1] = '\0';
        char *slash = strrchr(exec_dir, '/');
        if (slash) {
            *slash = '\0';
        } else {
            exec_dir[0] = '.'; exec_dir[1] = '\0';
        }
    } else {
        exec_dir[0] = '.'; exec_dir[1] = '\0';
    }
    /* Walk load commands for LC_RPATH */
    {
        uint8_t *lc_r = file_data + sizeof(mach_header_64);
        for (uint32_t i = 0; i < hdr->ncmds && lc_r + 8 <= lc_end; i++) {
            uint32_t cmd_r = *(uint32_t *)(void *)lc_r;
            uint32_t cmdsize_r = *(uint32_t *)(void *)(lc_r + 4);
            if (cmd_r == LC_RPATH && g_nrpaths < MAX_RPATHS) {
                /* LC_RPATH layout: cmd(4), cmdsize(4), path_offset(4), path... */
                uint32_t path_off = *(uint32_t *)(void *)(lc_r + 8);
                const char *rp = (const char *)(lc_r + path_off);
                /* Expand @loader_path and @executable_path to exec_dir */
                char expanded[4096];
                if (strncmp(rp, "@loader_path", 12) == 0) {
                    snprintf(expanded, sizeof(expanded), "%s%s", exec_dir, rp + 12);
                } else if (strncmp(rp, "@executable_path", 16) == 0) {
                    snprintf(expanded, sizeof(expanded), "%s%s", exec_dir, rp + 16);
                } else {
                    strncpy(expanded, rp, sizeof(expanded) - 1);
                    expanded[sizeof(expanded) - 1] = '\0';
                }
                g_rpaths[g_nrpaths++] = strdup(expanded);
                if (g_verbose)
                    fprintf(stderr, "macify: LC_RPATH %s -> %s\n", rp, expanded);
            }
            lc_r += cmdsize_r;
        }
    }

    /* Pre-load libc++ (LLVM C++ standard library) so that all subsequently
     * loaded Mach-O dylibs can resolve their C++ symbols via flat lookup.
     * macOS binaries use libc++ (std::__1 namespace), which is ABI-incompatible
     * with Linux's libstdc++ (std::__cxx11 namespace). We provide prebuilt
     * libc++.so.1, libc++abi.so.1, and libunwind.so.1 in the macify prefix. */
    {
        const char *mprefix = macify_get_prefix();
        char lib_path[4096];
        /* Load libunwind first (libc++abi depends on it) */
        snprintf(lib_path, sizeof(lib_path), "%s/usr/local/lib/libunwind.so.1", mprefix);
        void *unwind_h = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
        if (!unwind_h) unwind_h = dlopen("libunwind.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (unwind_h) register_extra_handle(unwind_h);
        /* Load libc++abi (depends on libunwind) */
        snprintf(lib_path, sizeof(lib_path), "%s/usr/local/lib/libc++abi.so.1", mprefix);
        void *cxxabi = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
        if (!cxxabi) cxxabi = dlopen("libc++abi.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (cxxabi) register_extra_handle(cxxabi);
        /* Load libc++ (depends on libc++abi) */
        snprintf(lib_path, sizeof(lib_path), "%s/usr/local/lib/libc++.so.1", mprefix);
        void *libcxx = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
        if (!libcxx) libcxx = dlopen("libc++.so.1", RTLD_NOW | RTLD_GLOBAL);
        if (libcxx) register_extra_handle(libcxx);
        if (g_verbose)
            fprintf(stderr, "macify: preloaded libc++ unwind=%p abi=%p libcxx=%p\n",
                    unwind_h, cxxabi, libcxx);
    }

    for (uint32_t i = 0; i < hdr->ncmds && lc + 8 <= lc_end; i++) {
        uint32_t cmd     = *(uint32_t *)(void *)lc;
        uint32_t cmdsize = *(uint32_t *)(void *)(lc + 4);
        if (cmdsize == 0 || lc + cmdsize > lc_end) {
            fprintf(stderr, "macify: malformed load command %u\n", i);
            return 1;
        }

        if (cmd == LC_SEGMENT_64) {
            segment_command_64 *seg = (segment_command_64 *)(void *)lc;
            if (map_segment(seg, file_data, file_size) < 0) return 1;
        } else if (cmd == LC_UNIXTHREAD) {
            uint32_t flavor = *(uint32_t *)(void *)(lc + 8);
            uint32_t count  = *(uint32_t *)(void *)(lc + 12);
            if (flavor == x86_THREAD_STATE64 && count == 42) {
                x86_thread_state64_t *ts = (x86_thread_state64_t *)(void *)(lc + 16);
                g_entry_rip = ts->rip + g_slide;  /* apply ASLR/PIE slide */
                if (g_verbose) {
                    fprintf(stderr, "macify: LC_UNIXTHREAD entry rip=%#lx (static=%#lx slide=%#lx) rsp=%#lx\n",
                            (unsigned long)g_entry_rip, (unsigned long)ts->rip,
                            (unsigned long)g_slide, (unsigned long)ts->rsp);
                }
            }
        } else if (cmd == LC_MAIN) {
            entry_point_command *ep = (entry_point_command *)(void *)lc;
            main_entryoff = ep->entryoff;
            have_main = 1;
            if (g_verbose) {
                fprintf(stderr, "macify: LC_MAIN entryoff=%#lx\n",
                        (unsigned long)ep->entryoff);
            }
        } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB ||
                   cmd == LC_REEXPORT_DYLIB || cmd == LC_LAZY_LOAD_DYLIB) {
            dylib_command *dc = (dylib_command *)(void *)lc;
            const char *name = (const char *)(lc + dc->name_offset);
            const char *cmd_name =
                (cmd == LC_LOAD_DYLIB)       ? "LC_LOAD_DYLIB" :
                (cmd == LC_LOAD_WEAK_DYLIB)  ? "LC_LOAD_WEAK_DYLIB" :
                (cmd == LC_REEXPORT_DYLIB)   ? "LC_REEXPORT_DYLIB" :
                                               "LC_LAZY_LOAD_DYLIB";

            /* Resolve @rpath/, @loader_path/, @executable_path/ prefixes.
             * @rpath/X — try each LC_RPATH entry as prefix for X
             * @loader_path/X — replace with executable's directory + X
             * @executable_path/X — same as @loader_path for the main binary
             * Returns a malloc'd resolved path, or NULL if not resolvable.
             * Sets `name` to point to the resolved path so the rest of the
             * logic uses it. */
            char *resolved_name = NULL;
            char resolved_buf[4096];
            if (strncmp(name, "@rpath/", 7) == 0) {
                const char *rest = name + 7;
                /* Try each rpath */
                for (int ri = 0; ri < g_nrpaths && !resolved_name; ri++) {
                    snprintf(resolved_buf, sizeof(resolved_buf), "%s/%s", g_rpaths[ri], rest);
                    if (access(resolved_buf, R_OK) == 0) {
                        resolved_name = resolved_buf;
                    }
                }
                if (!resolved_name && g_verbose) {
                    fprintf(stderr, "macify: @rpath not resolved for %s (tried %d rpaths)\n", name, g_nrpaths);
                    for (int ri = 0; ri < g_nrpaths; ri++) {
                        fprintf(stderr, "  rpath[%d]: %s\n", ri, g_rpaths[ri]);
                    }
                }
            } else if (strncmp(name, "@loader_path/", 13) == 0) {
                snprintf(resolved_buf, sizeof(resolved_buf), "%s/%s", exec_dir, name + 13);
                if (access(resolved_buf, R_OK) == 0)
                    resolved_name = resolved_buf;
            } else if (strncmp(name, "@executable_path/", 17) == 0) {
                snprintf(resolved_buf, sizeof(resolved_buf), "%s/%s", exec_dir, name + 17);
                if (access(resolved_buf, R_OK) == 0)
                    resolved_name = resolved_buf;
            }
            if (resolved_name) {
                /* Use resolved path (still need to load as Mach-O if it's a .dylib) */
                name = resolved_name;
                if (g_verbose)
                    fprintf(stderr, "macify: resolved dylib path -> %s\n", name);
            }

            if (g_ndylibs >= MAX_DYLIBS) {
                fprintf(stderr, "macify: too many dylibs (max %d)\n", MAX_DYLIBS);
                return 1;
            }
            /* Load shim and libc. The shim provides macOS-specific functions
             * (__errno, _NSGetEnviron, mach_*, objc_*, dispatch_*, etc.) that
             * glibc lacks; libc.so.6 provides standard C functions. We store
             * both handles — the bind interpreter tries the shim first, then
             * libc, then libm. RTLD_GLOBAL makes shim symbols visible to
             * subsequently-loaded libraries. */
            void *shim_handle = dlopen("libmacify_shim.so", RTLD_NOW | RTLD_GLOBAL);
            void *libc_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_GLOBAL);
            void *libm_handle = dlopen("libm.so.6", RTLD_NOW | RTLD_GLOBAL);

            /* Map macOS library names to Linux equivalents.
             * IMPORTANT: @@HOMEBREW_PREFIX@@ and resolved (@rpath/@loader_path)
             * paths are checked FIRST — they're Mach-O dylibs that need our
             * Mach-O loader, not Linux's dlopen (which expects ELF). */
            void *extra1 = NULL;
            if (strstr(name, "@@HOMEBREW_CELLAR@@") ||
                       strstr(name, "@@HOMEBREW_PREFIX@@")) {
                /* Homebrew bottle placeholder paths — these are Mach-O dylibs
                 * that need to be loaded through our own Mach-O dylib loader,
                 * not Linux's dlopen (which expects ELF format). */
                const char *mprefix = macify_get_prefix();
                char real_path[4096];
                const char *rest;
                if (strstr(name, "@@HOMEBREW_CELLAR@@")) {
                    rest = name + strlen("@@HOMEBREW_CELLAR@@");
                    snprintf(real_path, sizeof(real_path), "%s/usr/local/Cellar%s", mprefix, rest);
                } else {
                    rest = name + strlen("@@HOMEBREW_PREFIX@@");
                    snprintf(real_path, sizeof(real_path), "%s/usr/local%s", mprefix, rest);
                }
                /* Load as Mach-O dylib (not dlopen which expects ELF) */
                int rc = macho_load_dylib(real_path);
                if (g_verbose) {
                    if (rc == 0)
                        fprintf(stderr, "macify:   loaded Mach-O dylib: %s\n", real_path);
                    else
                        fprintf(stderr, "macify:   WARNING: failed to load Mach-O dylib: %s\n", real_path);
                }
                /* extra1 stays NULL — the dylib's symbols are available
                 * via macho_dylib_lookup() in resolve_symbol() */
                extra1 = NULL;
            } else if (resolved_name) {
                /* The path was resolved via @rpath/@loader_path/@executable_path
                 * and points to a real Mach-O .dylib file. Defer loading until
                 * after all other dylibs (which may be its dependencies) are
                 * loaded and registered. We collect these in a list and load
                 * them after the main load-command walk completes. */
                if (g_ndeferred_dylibs < MAX_DEFERRED_DYLIBS) {
                    strncpy(g_deferred_dylibs[g_ndeferred_dylibs], resolved_name,
                            sizeof(g_deferred_dylibs[0]) - 1);
                    g_deferred_dylibs[g_ndeferred_dylibs][sizeof(g_deferred_dylibs[0]) - 1] = '\0';
                    g_ndeferred_dylibs++;
                }
                extra1 = NULL;
            } else if (strstr(name, "libc++") || strstr(name, "libc++abi") ||
                       strstr(name, "libunwind")) {
                /* macOS C++ standard library — already preloaded before the
                 * main walk. Nothing to do here. */
                extra1 = NULL;
            } else if (strstr(name, "libncurses")) {
                extra1 = dlopen("libncursesw.so.6", RTLD_NOW | RTLD_GLOBAL);
                if (!extra1) extra1 = dlopen("libncurses.so.6", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libz")) {
                extra1 = dlopen("libz.so.1", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libresolv")) {
                extra1 = dlopen("libresolv.so.2", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libiconv")) {
                extra1 = dlopen("libiconv.so.2", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libssl")) {
                extra1 = dlopen("libssl.so.3", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libcrypto")) {
                extra1 = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libgnutls")) {
                extra1 = dlopen("libgnutls.so.30", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libnettle")) {
                extra1 = dlopen("libnettle.so.8", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libpcre2")) {
                extra1 = dlopen("libpcre2-8.so.0", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libpsl")) {
                extra1 = dlopen("libpsl.so.5", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libidn2")) {
                extra1 = dlopen("libidn2.so.0", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libunistring")) {
                extra1 = dlopen("libunistring.so.5", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libedit")) {
                extra1 = dlopen("libedit.so.2", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libreadline")) {
                extra1 = dlopen("libreadline.so.8", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libmagic")) {
                extra1 = dlopen("libmagic.so.1", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libcurl")) {
                extra1 = dlopen("libcurl.so.4", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libssh2")) {
                extra1 = dlopen("libssh2.so.1", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libnghttp3")) {
                extra1 = dlopen("libnghttp3.so.9", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libnghttp2")) {
                extra1 = dlopen("libnghttp2.so.14", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libzstd")) {
                extra1 = dlopen("libzstd.so.1", RTLD_NOW | RTLD_GLOBAL);
            } else if (strstr(name, "libintl")) {
                /* libintl is part of glibc on Linux — no separate library */
                extra1 = NULL;
            }
            if (extra1) {
                register_extra_handle(extra1);
                if (g_verbose)
                    fprintf(stderr, "macify:   extra1 loaded for \"%s\"\n", name);
            } else if (g_verbose) {
                /* Check if this dylib should have had an extra but didn't */
                if (strstr(name, "libssl") || strstr(name, "libcrypto") ||
                    strstr(name, "libcurl") || strstr(name, "libssh2") ||
                    strstr(name, "libnghttp") || strstr(name, "libzstd") ||
                    strstr(name, "libpsl") || strstr(name, "libz") ||
                    strstr(name, "libiconv") || strstr(name, "libresolv"))
                    fprintf(stderr, "macify:   WARNING: no extra1 loaded for \"%s\"\n", name);
            }

            if (!shim_handle || !libc_handle) {
                fprintf(stderr, "macify: failed to load shim/libc for %s: shim=%p libc=%p: %s\n",
                        name, shim_handle, libc_handle, dlerror());
                return 1;
            }
            strncpy(g_dylibs[g_ndylibs].name, name, 255);
            g_dylibs[g_ndylibs].name[255] = '\0';
            g_dylibs[g_ndylibs].handle = shim_handle;
            g_dylibs[g_ndylibs].libc_handle = libc_handle;
            g_dylibs[g_ndylibs].libm_handle = libm_handle;  /* may be NULL */
            g_ndylibs++;
            if (g_verbose) {
                fprintf(stderr, "macify: %s \"%s\" -> libmacify_shim.so + libc.so.6 (ordinal %d)\n",
                        cmd_name, name, g_ndylibs);
            }
        } else if (cmd == LC_DYLD_INFO_ONLY) {
            dyld_info_command *di = (dyld_info_command *)(void *)lc;
            g_rebase_off      = di->rebase_off;
            g_rebase_size     = di->rebase_size;
            g_bind_off        = di->bind_off;
            g_bind_size       = di->bind_size;
            g_lazy_bind_off   = di->lazy_bind_off;
            g_lazy_bind_size  = di->lazy_bind_size;
            if (g_verbose) {
                fprintf(stderr, "macify: LC_DYLD_INFO_ONLY rebase=%u+%u bind=%u+%u lazy_bind=%u+%u\n",
                        g_rebase_off, g_rebase_size,
                        g_bind_off, g_bind_size,
                        g_lazy_bind_off, g_lazy_bind_size);
            }
        } else if (cmd == LC_SYMTAB) {
            symtab_command *st = (symtab_command *)(void *)lc;
            g_symtab_off   = st->symoff;
            g_symtab_nsyms = st->nsyms;
            g_strtab_off   = st->stroff;
            g_strtab_size  = st->strsize;
            if (g_verbose) {
                fprintf(stderr, "macify: LC_SYMTAB symoff=%u nsyms=%u stroff=%u strsize=%u\n",
                        g_symtab_off, g_symtab_nsyms, g_strtab_off, g_strtab_size);
            }
        } else if (cmd == LC_DYSYMTAB) {
            dysymtab_command *dst = (dysymtab_command *)(void *)lc;
            g_indirectsym_off   = dst->indirectsymoff;
            g_indirectsym_count = dst->nindirectsyms;
            if (g_verbose && g_indirectsym_count > 0) {
                fprintf(stderr, "macify: LC_DYSYMTAB indirectsym=%u+%u\n",
                        g_indirectsym_off, g_indirectsym_count);
            }
        } else if (cmd == LC_DYLD_CHAINED_FIXUPS) {
            /* Modern macOS chained fixups (replaces LC_DYLD_INFO binds) */
            uint32_t cf_off = *(uint32_t *)(void *)(lc + 8);
            uint32_t cf_size = *(uint32_t *)(void *)(lc + 12);
            g_chained_fixups_off = cf_off;
            g_chained_fixups_size = cf_size;
            g_has_chained_fixups = true;
            if (g_verbose) {
                fprintf(stderr, "macify: LC_DYLD_CHAINED_FIXUPS off=%u size=%u\n",
                        cf_off, cf_size);
            }
        }
        lc += cmdsize;
    }

    /* Now load deferred dylibs (those resolved via @rpath/@loader_path).
     * These are loaded AFTER all @@HOMEBREW_PREFIX@@ and system dylibs so
     * their dependencies are available via flat lookup. */
    for (int di = 0; di < g_ndeferred_dylibs; di++) {
        int rc = macho_load_dylib(g_deferred_dylibs[di]);
        if (g_verbose) {
            if (rc == 0)
                fprintf(stderr, "macify:   loaded deferred Mach-O dylib: %s\n", g_deferred_dylibs[di]);
            else
                fprintf(stderr, "macify:   WARNING: failed to load deferred Mach-O dylib: %s\n", g_deferred_dylibs[di]);
        }
    }

    /* Compute entry from LC_MAIN if present. */
    if (g_entry_rip == 0 && have_main) {
        for (int i = 0; i < g_nsegments; i++) {
            if (strcmp(g_segments[i].name, "__TEXT") == 0) {
                g_entry_rip = g_segments[i].vmaddr + main_entryoff;
                /* Save text range for SIGSEGV recovery in crash_handler. */
                g_macos_text_lo = g_segments[i].vmaddr;
                g_macos_text_hi = g_segments[i].vmaddr + g_segments[i].vmsize;
                break;
            }
        }
    }
    if (g_entry_rip == 0) {
        fprintf(stderr, "macify: no entry point found\n");
        return 1;
    }

    /* Patch syscalls in executable segments. */
    for (int i = 0; i < g_nsegments; i++) {
        if (patch_syscalls_in_segment(&g_segments[i]) < 0) return 1;
    }
    if (g_verbose) {
        fprintf(stderr, "macify: total — fast=%lu, slow=%lu\n",
                g_fast_path_sites, g_slow_path_sites);
    }

    /* Patch macOS getc macros AND __SEOF/__SERR checks together.
     *
     * ROOT PROBLEM: macOS FILE struct has _r (int, 4 bytes) at offset 8
     * and __SEOF/__SERR flags (bits 0x20/0x40) at offset 0x10. glibc has
     * _IO_read_ptr (char*, 8 bytes) at offset 8 and _IO_read_end (char*)
     * at offset 0x10. They overlap.
     *
     * The macOS getc macro does: --_r; if (_r >= 0) read *_p. The "--_r"
     * store corrupts _IO_read_ptr. macOS code also checks [fp+0x10] & 0x20
     * for EOF and [fp+0x10] & 0x40 for error — these are glibc's _IO_read_end
     * pointer, whose low byte can have bits 0x20/0x40 set, causing false
     * EOF/error detection.
     *
     * SKIP for large/complex binaries (text > 100KB) — the pattern matching
     * is too aggressive and can corrupt unrelated code. The 0xfbad2000 page
     * mapping (in the shim constructor) handles the crash case safely.
     * Enable with MACIFY_PATCH_EOF=1 for binaries that need it.
     *
     * FIX (only when BOTH patterns are found):
     *   1. NOP the getc macro's _r store (prevents _IO_read_ptr corruption)
     *   2. Change getc's jle to jmp (always call __srget for correct data)
     *   3. NOP the __SEOF/__SERR check's conditional jump (prevent false EOF)
     *   4. Set macify_getc_patched=1 so __srget doesn't set _r = -1
     *
     * If only getc macros are found (no EOF checks), the old _r = -1
     * approach is used — it's safer for binaries that don't check __SEOF. */
    {
        loaded_section *text_sec = find_section("__TEXT", "__text");
        if (text_sec) {
            uint8_t *text = (uint8_t *)(uintptr_t)text_sec->addr;
            size_t size = text_sec->size;

            /* Skip EOF/getc patching for large binaries or when disabled.
             * The pattern matching is too aggressive for complex programs
             * like bash — it corrupts unrelated code. The 0xfbad2000 page
             * mapping handles the crash case safely. */
            if (size > 100000 && !getenv("MACIFY_PATCH_EOF")) {
                if (g_verbose)
                    fprintf(stderr, "macify: skipping __SEOF/__SERR patching (text=%zu bytes > 100KB)\n", size);
                goto skip_eof_patch;
            }

            /* Step 1: Count __SEOF/__SERR checks */
            int eof_check_count = 0;
            for (size_t i = 0; i + 7 < size; i++) {
                size_t off = i;
                int has_rex = 0;
                if (text[off] == 0x41) { has_rex = 1; off++; }
                if (text[off] != 0xf6) continue;
                if ((text[off+1] & 0xF8) != 0x40) continue;
                if (text[off+2] != 0x10) continue;
                if (text[off+3] != 0x20 && text[off+3] != 0x40) continue;
                size_t after = i + 4 + has_rex;
                if (text[after] == 0x75 || text[after] == 0x74 ||
                    (text[after] == 0x0f && (text[after+1] == 0x85 || text[after+1] == 0x84)))
                    eof_check_count++;
            }

            /* Step 2: Only patch getc macros if EOF checks are also present */
            if (eof_check_count > 0) {
                /* Patch __SEOF/__SERR checks first.
                 *
                 * The test instruction checks [fp+0x10] & {0x20|0x40}.
                 * The conditional jump after it goes to either:
                 *   - the error/EOF handler (if bit set), or
                 *   - the normal path (if bit not set)
                 *
                 * We want to ALWAYS take the normal path (bit not set).
                 *
                 * For je (0x74/0x0f84): jumps when bit NOT set → normal path.
                 *   Change to jmp (always take normal path).
                 *   Short: 74 XX → eb XX
                 *   Near:  0f 84 XX XX XX XX → e9 XX XX XX XX 90
                 *
                 * For jne (0x75/0x0f85): jumps when bit set → error path.
                 *   NOP it (fall through to normal path).
                 *   Short: 75 XX → 90 90
                 *   Near:  0f 85 XX XX XX XX → 90 90 90 90 90 90 */
                int eof_patched = 0;
                for (size_t i = 0; i + 7 < size; i++) {
                    size_t off = i;
                    int has_rex = 0;
                    if (text[off] == 0x41) { has_rex = 1; off++; }
                    if (text[off] != 0xf6) continue;
                    if ((text[off+1] & 0xF8) != 0x40) continue;
                    if (text[off+2] != 0x10) continue;
                    if (text[off+3] != 0x20 && text[off+3] != 0x40) continue;
                    size_t after = i + 4 + has_rex;
                    uintptr_t page = (uintptr_t)(text + after) & ~0xfffUL;

                    if (text[after] == 0x74) {
                        /* je short → jmp short (always take no-error path) */
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
                        text[after] = 0xeb;
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_EXEC);
                        eof_patched++;
                    } else if (text[after] == 0x75) {
                        /* jne short → NOP (fall through to no-error path) */
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
                        text[after] = 0x90; text[after + 1] = 0x90;
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_EXEC);
                        eof_patched++;
                    } else if (text[after] == 0x0f && text[after+1] == 0x84) {
                        /* je near → jmp near (always take no-error path)
                         * je near:  0f 84 D1 D2 D3 D4 (6 bytes, target = ip+6+disp)
                         * jmp near: e9 D1 D2 D3 D4 90 (5 bytes, target = ip+5+disp)
                         * To keep same target: new_disp = disp + 1 */
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
                        /* Read original displacement */
                        int32_t disp = (int32_t)(text[after+2] | (text[after+3]<<8) |
                                       (text[after+4]<<16) | (text[after+5]<<24));
                        disp += 1;  /* Adjust for shorter instruction */
                        text[after] = 0xe9;
                        text[after+1] = disp & 0xff;
                        text[after+2] = (disp >> 8) & 0xff;
                        text[after+3] = (disp >> 16) & 0xff;
                        text[after+4] = (disp >> 24) & 0xff;
                        text[after+5] = 0x90;  /* NOP padding */
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_EXEC);
                        eof_patched++;
                    } else if (text[after] == 0x0f && text[after+1] == 0x85) {
                        /* jne near → NOP (fall through to no-error path) */
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
                        for (int s = 0; s < 6; s++) text[after + s] = 0x90;
                        mprotect((void *)page, 0x1000, PROT_READ | PROT_EXEC);
                        eof_patched++;
                    }
                }

                /* Patch getc macros */
                int getc_patched = 0;
                for (size_t i = 3; i + 16 < size; i++) {
                    if (text[i] != 0x8d || text[i+1] != 0x48 || text[i+2] != 0xff) continue;
                    int load_rex = 0, load_rm = -1;
                    if (i >= 4 && text[i-4] == 0x41 && text[i-3] == 0x8b && text[i-1] == 0x08) {
                        load_rex = 1; load_rm = text[i-2] & 0x07;
                    } else if (i >= 3 && text[i-3] == 0x8b && text[i-1] == 0x08) {
                        load_rex = 0; load_rm = text[i-2] & 0x07;
                    }
                    if (load_rm < 0) continue;
                    int store_start = -1, store_len = 0;
                    for (size_t j = i + 3; j < i + 8 && j + 3 < size; j++) {
                        int has_rex = 0; size_t off = j;
                        if (text[off] == 0x41) { has_rex = 1; off++; }
                        if (text[off] == 0x89 && (text[off+1] & 0xF8) == 0x48 && text[off+2] == 0x08) {
                            if ((text[off+1] & 0x07) == load_rm && has_rex == load_rex) {
                                store_start = (int)j; store_len = 3 + has_rex; break;
                            }
                        }
                    }
                    if (store_start < 0) continue;
                    size_t after = (size_t)store_start + store_len;
                    if (after + 3 >= size) continue;
                    if (text[after] != 0x85 || text[after+1] != 0xc0 || text[after+2] != 0x7e) continue;
                    uintptr_t page = (uintptr_t)(text + store_start) & ~0xfffUL;
                    mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
                    for (int s = 0; s < store_len; s++) text[store_start + s] = 0x90;
                    text[after + 2] = 0xeb;
                    mprotect((void *)page, 0x1000, PROT_READ | PROT_EXEC);
                    getc_patched++;
                }

                if (g_verbose && (eof_patched || getc_patched)) {
                    fprintf(stderr, "macify: patched %d __SEOF/__SERR check(s), %d getc macro(s)\n",
                            eof_patched, getc_patched);
                }
                if (eof_patched > 0 && getc_patched > 0) {
                    int *flag = (int *)dlsym(g_dylibs[0].handle, "macify_getc_patched");
                    if (flag) *flag = 1;
                }
            }
        }
    }
    skip_eof_patch: ;

    /* Patch inlined putc macros to always call __swbuf.
     *
     * macOS's putc macro: --_w >= 0 ? (*_p++ = ch) : __swbuf(ch, fp)
     * When using glibc's FILE, _w (offset 0x0c) overlaps with _IO_read_ptr's
     * upper bytes, and _p (offset 0) is _flags (0xfbad2084). Characters
     * written via the fast path (*_p++ = ch) go to the safety page and
     * are lost.
     *
     * We patch the `jg` (if _w > 0, write directly) to `jmp` (always call
     * __swbuf). This routes ALL characters through our __swbuf override,
     * which calls glibc's real fputc for correct buffering.
     *
     * Pattern (x86_64):
     *   8b 8X 0c 00 00 00   mov ecx, [rX+0x0c]    (read _w)
     *   8d 5X ff            lea edx, [rcx-1]       (_w-1)
     *   89 9X 0c 00 00 00   mov [rX+0x0c], edx     (write _w)
     *   85 c9               test ecx, ecx
     *   7f XX               jg XX                  (if _w > 0, write directly)
     *   3c 0a               cmp al, 0xa            (if char == '\n')
     *   74 YY               je ZZ                  (call __swbuf for newline)
     *
     * Change 7f XX → eb (4+YY) to always jump to the __swbuf path.
     */
    {
        loaded_section *text_sec = find_section("__TEXT", "__text");
        if (text_sec) {
            uint8_t *text = (uint8_t *)(uintptr_t)text_sec->addr;
            size_t size = text_sec->size;
            int patched = 0;
            for (size_t i = 0; i + 16 < size; i++) {
                /* Pattern (3-byte instructions):
                 *   8b 4X 0c            mov ecx, [rX+0x0c]    (read _w)
                 *   8d 51 ff            lea edx, [rcx-1]       (_w-1)
                 *   89 5X 0c            mov [rX+0x0c], edx     (write _w)
                 *   85 c9               test ecx, ecx
                 *   7f XX               jg XX                  (if _w > 0, write directly)
                 *   3c 0a               cmp al, 0xa            (if char == '\n')
                 *   74 YY               je ZZ                  (call __swbuf for newline)
                 */
                /* Check for: mov ecx, [rX+0x0c] (3 bytes) */
                if (text[i] != 0x8b) continue;
                uint8_t modrm1 = text[i+1];
                if ((modrm1 & 0xC0) != 0x40) continue;  /* mod=01 (8-bit disp) */
                if ((modrm1 & 0x38) != 0x08) continue;  /* reg=ecx */
                int reg = modrm1 & 0x07;
                if (text[i+2] != 0x0c) continue;

                /* Check for: lea edx, [rcx-1] (3 bytes) */
                if (text[i+3] != 0x8d) continue;
                if (text[i+4] != 0x51) continue;
                if (text[i+5] != 0xff) continue;

                /* Check for: mov [rX+0x0c], edx (3 bytes) */
                if (text[i+6] != 0x89) continue;
                uint8_t modrm2 = text[i+7];
                if ((modrm2 & 0xC0) != 0x40) continue;
                if ((modrm2 & 0x38) != 0x10) continue;  /* reg=edx */
                if ((modrm2 & 0x07) != reg) continue;    /* same base reg */
                if (text[i+8] != 0x0c) continue;

                /* Check for: test ecx, ecx (2 bytes) */
                if (text[i+9] != 0x85) continue;
                if (text[i+10] != 0xc9) continue;

                /* Check for: jg XX (2 bytes) */
                if (text[i+11] != 0x7f) continue;

                /* Check for: cmp al, 0xa (2 bytes) */
                if (text[i+13] != 0x3c) continue;
                if (text[i+14] != 0x0a) continue;

                /* Check for: je YY (2 bytes) */
                if (text[i+15] != 0x74) continue;
                uint8_t je_offset = text[i+16];

                /* Patch: change jg to jmp to the __swbuf path.
                 * jg is at i+11, je is at i+15.
                 * je target = (i+15) + 2 + je_offset = i + 17 + je_offset
                 * jmp offset = je_target - (jg + 2) = (i + 17 + je_offset) - (i + 13) = 4 + je_offset
                 */
                uintptr_t page = (uintptr_t)(text + i) & ~0xfffUL;
                if (mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                    fprintf(stderr, "macify: mprotect RWX FAILED for putc patch at %p: %s\n", (void*)(text+i), strerror(errno));
                    continue;
                }
                /* NOP the write to [rX+0x0c] (3 bytes at i+6) to prevent
                 * _IO_read_ptr corruption */
                text[i+6] = 0x90; text[i+7] = 0x90; text[i+8] = 0x90;
                /* Change jg to jmp to always call __swbuf */
                text[i+11] = 0xeb;  /* jmp short */
                text[i+12] = 4 + je_offset;
                mprotect((void *)page, 0x1000, PROT_READ | PROT_EXEC);
                /* Verify the patch was applied */
                if (text[i+11] != 0xeb || text[i+6] != 0x90) {
                    fprintf(stderr, "macify: putc patch VERIFY FAILED at %p (got %02x %02x)\n",
                            (void*)(text+i+11), text[i+11], text[i+6]);
                } else if (g_verbose) {
                    fprintf(stderr, "macify: putc patch OK at %p (NOP+jmp %d)\n", (void*)(text+i+11), 4+je_offset);
                }
                patched++;
            }
            if (g_verbose && patched > 0)
                fprintf(stderr, "macify: patched %d putc macro(s) to call __swbuf\n", patched);
        }
    }

    /* Patch close_stdout to return 0 immediately.
     * macOS close_stdout checks [FILE* + 0x10] & 0x40 for __SERR (error).
     * Glibc stores _IO_read_end (buffer pointer) at offset 0x10, which
     * may have bit 0x40 set, causing false "write error" exit codes.
     * We find _close_stdout in the binary symbol table and patch its first
     * instructions to: xor eax, eax; ret (return 0). */
    if (g_symtab_off > 0 && g_symtab_nsyms > 0 && g_slide != 0) {
        for (uint32_t i = 0; i < g_symtab_nsyms; i++) {
            nlist_64 *nl = (nlist_64 *)(file_data + g_symtab_off + i * 16);
            if ((nl->n_type & 0x0e) != 0x0e) continue;  /* not a section symbol */
            const char *name = (const char *)(file_data + g_strtab_off + nl->n_strx);
            if (name[0] == '_') name++;
            if (strcmp(name, "close_stdout") == 0 ||
                strcmp(name, "close_stream") == 0 ||
                strcmp(name, "flush_stdout") == 0) {
                uintptr_t addr = (uintptr_t)nl->n_value + g_slide;
                mprotect((void *)(addr & ~0xfff), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
                uint8_t *p = (uint8_t *)addr;
                p[0] = 0x31; p[1] = 0xc0; p[2] = 0xc3;  /* xor eax,eax; ret */
                mprotect((void *)(addr & ~0xfff), 0x1000, PROT_READ | PROT_EXEC);
                if (g_verbose) {
                    fprintf(stderr, "macify: patched %s at %p\n", name, (void *)addr);
                }
            }
        }
    }

    /* Execute rebase opcodes (adjust internal pointers for slide). */
    if (g_rebase_size > 0) {
        if (execute_rebases(file_data, file_size) < 0) return 1;
    }

    /* Execute bind opcodes (non-lazy: resolve external symbols, fill __got). */
    if (g_bind_size > 0) {
        if (execute_binds(file_data, file_size) < 0) return 1;
    }

    /* Execute lazy bind opcodes. Real dyld resolves these on first call via
     * dyld_stub_binder; we eagerly resolve them all at load time. */
    if (g_lazy_bind_size > 0) {
        if (execute_lazy_binds(file_data, file_size) < 0) return 1;
    }

    /* Execute chained fixups (modern macOS 11+ format; replaces LC_DYLD_INFO
     * bind/rebase opcodes for newer binaries). */
    if (g_has_chained_fixups) {
        if (execute_chained_fixups(file_data, file_size) < 0) return 1;
    }

    /* Resolve __got and __la_symbol_ptr entries using the indirect symbol
     * table. This is needed for binaries that use LC_DYLD_CHAINED_FIXUPS
     * (which only processes chained fixup entries, not all GOT entries).
     * Functions like __swbuf are in __got but NOT in the chained fixups. */
    if (g_indirectsym_off > 0 && g_symtab_off > 0 && g_strtab_off > 0) {
        int resolved = 0, unresolved = 0;
        for (int si = 0; si < g_nsections; si++) {
            loaded_section *s = &g_sections[si];
            uint32_t sec_type = s->flags & 0xff;
            if ((sec_type == 7 || sec_type == 6) && s->reserved1 > 0) {
                uint32_t start_idx = s->reserved1;
                uint32_t n_entries = s->size / 8;
                uint32_t *indirect = (uint32_t *)(file_data + g_indirectsym_off);
                const char *strtab = (const char *)(file_data + g_strtab_off);
                nlist_64 *syms = (nlist_64 *)(file_data + g_symtab_off);
                for (uint32_t k = 0; k < n_entries; k++) {
                    uint32_t sym_idx = indirect[start_idx + k];
                    if (sym_idx & 0x80000000) continue;
                    if (sym_idx >= g_symtab_nsyms) continue;
                    nlist_64 *nl = &syms[sym_idx];
                    if (nl->n_strx >= g_strtab_size) continue;
                    const char *name = strtab + nl->n_strx;
                    if (name[0] == '_') name++;
                    void *addr = resolve_symbol(-1, name);
                    if (addr) {
                        *(uint64_t *)(uintptr_t)(s->addr + k * 8) = (uint64_t)(uintptr_t)addr;
                        /* Debug: verify critical symbols */
                        if (g_verbose && (strcmp(name, "sigprocmask") == 0 || strcmp(name, "fork") == 0 || strcmp(name, "write") == 0))
                            fprintf(stderr, "macify: GOT %s at %p = 0x%lx\n", name,
                                    (void*)(uintptr_t)(s->addr + k * 8),
                                    (unsigned long)*(uint64_t*)(uintptr_t)(s->addr + k * 8));
                        resolved++;
                    } else {
                        unresolved++;
                        if (g_verbose)
                            fprintf(stderr, "macify: UNRESOLVED %s.%s[%u]: %s\n",
                                    s->segname, s->sectname, k, name);
                    }
                }
            }
        }
        if (g_verbose && resolved > 0)
            fprintf(stderr, "macify: main binary GOT/la_symbol_ptr: %d resolved, %d unresolved\n",
                    resolved, unresolved);
    }

    /* Switch to macOS FILE structs if the binary uses inlined putc macros.
     * Detected by text section size > 100KB (bash, node, etc.).
     * Small binaries (echo, cat, ls) work fine with glibc's FILE. */
    if (g_ndylibs > 0 && g_dylibs[0].handle) {
        loaded_section *text_sec = find_section("__TEXT", "__text");
        if (text_sec && text_sec->size > 100000) {
            /* Use _w=-1 approach: force glibc's _IO_read_ptr upper 4 bytes
             * (macOS _w at offset 0x0c) to -1 so the inlined putc macro
             * always calls __swbuf (which we intercept).
             * This is done right before calling main in runtime.c.
             * We don't use macOS FILE structs because they conflict with
             * glibc's buffer pointer layout. */
            if (g_verbose)
                fprintf(stderr, "macify: will set _w=-1 for inlined putc (text=%zu bytes > 100KB)\n",
                        text_sec->size);
        }
    }

    /* Set up TLV (Thread-Local Variable) info in the shim. Find __thread_data
     * and __thread_bss sections and pass them to __macify_set_tlv_info() so
     * the shim can allocate per-thread TLV blocks. Must run before main(). */
    if (g_ndylibs > 0 && g_dylibs[0].handle) {
        /* Set up TLV info */
        void (*set_tlv)(void *, size_t, size_t) =
            (void (*)(void *, size_t, size_t))dlsym(g_dylibs[0].handle,
                                                     "__macify_set_tlv_info");
        if (set_tlv) {
            loaded_section *td = find_section("__DATA", "__thread_data");
            loaded_section *tb = find_section("__DATA", "__thread_bss");
            void *data_base = td ? (void *)(uintptr_t)td->addr : NULL;
            size_t data_size = td ? td->size : 0;
            size_t bss_size = tb ? tb->size : 0;
            set_tlv(data_base, data_size, bss_size);
            if (g_verbose) {
                fprintf(stderr, "macify: TLV info set: data=%p+%zu bss=%zu\n",
                        data_base, data_size, bss_size);
            }
        }

        /* Set up argc/argv/environ/exec_path for _NSGetArgc etc. */
        void (*set_args)(int, char **, const char *) =
            (void (*)(int, char **, const char *))dlsym(g_dylibs[0].handle,
                                                         "__macify_set_args");
        if (set_args) {
            set_args(app_argc, app_argv, path);
            if (g_verbose) {
                fprintf(stderr, "macify: args set: argc=%d argv=%p path=%s\n",
                        app_argc, (void *)app_argv, path);
            }
        }

        /* Set the image header (load base) for _dyld_get_image_header().
         * This must be the SLID address of the first non-PAGEZERO segment. */
        void (*set_header)(uint64_t) =
            (void (*)(uint64_t))dlsym(g_dylibs[0].handle,
                                      "__macify_set_image_header");
        if (set_header) {
            uint64_t header = 0;
            for (int si = 0; si < g_nsegments; si++) {
                if (!g_segments[si].is_pagezero) {
                    header = g_segments[si].vmaddr;  /* already slid */
                    break;
                }
            }
            set_header(header);
            if (g_verbose) {
                fprintf(stderr, "macify: image header set to %#lx\n",
                        (unsigned long)header);
            }
        }

        /* Set the macOS binary's text range so the shim knows which calls
         * come from macOS code (and need flag/path translation) vs macify's
         * own code (which should pass through). Without this, ALL shim
         * overrides treat callers as non-macOS, skipping flag translation
         * and path translation — causing open() with macOS flags to fail. */
        {
            void (*set_text_range)(uint64_t, uint64_t) =
                (void (*)(uint64_t, uint64_t))dlsym(g_dylibs[0].handle,
                                                     "__macify_set_text_range");
            if (set_text_range) {
                for (int si = 0; si < g_nsegments; si++) {
                    if (strcmp(g_segments[si].name, "__TEXT") == 0) {
                        set_text_range(g_segments[si].vmaddr,
                                       g_segments[si].vmaddr + g_segments[si].vmsize);
                        if (g_verbose) {
                            fprintf(stderr, "macify: text range set to [%#lx, %#lx)\n",
                                    (unsigned long)g_segments[si].vmaddr,
                                    (unsigned long)(g_segments[si].vmaddr + g_segments[si].vmsize));
                        }
                        break;
                    }
                }
            }
        }

            /* Pre-resolve shim symbols for the SIGILL handler.
             * This avoids calling dlsym() inside the signal handler
             * (dlsym is not async-signal-safe). */
            sigill_handler_pre_resolve();
            /* Force OpenSSL init globals to success ONLY when explicitly
             * requested via MACIFY_FORCE_SSL=1 env var. The old code
             * auto-detected curl/wget by path substring, but the hardcoded
             * addresses are version-pinned and crash other binaries. */
            if (getenv("MACIFY_FORCE_SSL")) {
                void (*force_ssl)(void) =
                    (void (*)(void))dlsym(g_dylibs[0].handle,
                                          "macify_force_ssl_init_success");
                if (force_ssl) force_ssl();
            }
    }

    /* Run module initializers (__mod_init_func section). These function
     * pointers are called by dyld BEFORE main() to initialize C++ static
     * constructors, Objective-C categories, and other runtime state. */
    {
        loaded_section *init_sec = find_section("__DATA", "__mod_init_func");
        if (!init_sec) {
            /* Some binaries put it in __DATA_CONST */
            init_sec = find_section("__DATA_CONST", "__mod_init_func");
        }
        if (init_sec && init_sec->size > 0) {
            uint64_t *funcs = (uint64_t *)(uintptr_t)init_sec->addr;
            size_t count = init_sec->size / sizeof(uint64_t);
            if (g_verbose) {
                fprintf(stderr, "macify: running %zu module initializers from %s.%s\n",
                        count, init_sec->segname, init_sec->sectname);
            }
            for (size_t i = 0; i < count; i++) {
                uint64_t func_addr = funcs[i];  /* already rebased */
                if (func_addr == 0) continue;
                if (g_verbose) {
                    fprintf(stderr, "macify:   init[%zu] = %#lx\n", i, (unsigned long)func_addr);
                }
                ((void (*)(void))(uintptr_t)func_addr)();
            }
        }
    }

    /* Enforce segment protections after all fixups are applied.
     * macOS dyld downgrades __DATA_CONST to read-only after binding. */
    for (int i = 0; i < g_nsegments; i++) {
        if (g_segments[i].is_pagezero) continue;
        if (g_segments[i].prot != g_segments[i].target_prot) {
            if (mprotect((void *)(uintptr_t)g_segments[i].vmaddr,
                         g_segments[i].vmsize,
                         g_segments[i].target_prot) < 0) {
                if (g_verbose) {
                    fprintf(stderr, "macify: warning: mprotect %s to prot %d failed: %s\n",
                            g_segments[i].name, g_segments[i].target_prot, strerror(errno));
                }
            } else if (g_verbose) {
                fprintf(stderr, "macify: enforced prot %d on %s\n",
                        g_segments[i].target_prot, g_segments[i].name);
            }
            g_segments[i].prot = g_segments[i].target_prot;
        }
    }

    /* For Go binaries: set GODEBUG=asyncpreemptoff=1 and GOMAXPROCS=1
     * BEFORE setup_stack, so they appear in the envp array passed to main.
     * Go reads these during runtime.schedinit (very early in startup).
     *
     * We detect Go binaries by scanning the entry point for the GS test
     * pattern (mov gs:[0x30], 0x123). This is the same check that
     * setup_gs_base does later. */
    {
        int is_go = 0;
        if (g_entry_rip) {
            uint8_t *code = (uint8_t *)g_entry_rip;
            static const uint8_t gs_test[] = {
                0x65, 0x48, 0xc7, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x23, 0x01, 0x00, 0x00
            };
            for (unsigned int i = 0; i < 0x400 - sizeof(gs_test); i++) {
                if (memcmp(code + i, gs_test, sizeof(gs_test)) == 0) {
                    is_go = 1;
                    break;
                }
            }
        }
        if (is_go) {
            setenv("GODEBUG", "asyncpreemptoff=1", 0);
            setenv("GOMAXPROCS", "1", 0);
            if (g_verbose) {
                fprintf(stderr, "macify: Go binary detected — setting GODEBUG=asyncpreemptoff=1 GOMAXPROCS=1\n");
            }
        }
    }

    /* Initialize the macOS filesystem prefix (~/.macify/).
     * This creates ~/Library/Caches/, ~/Library/Preferences/, etc.
     * so macOS binaries find their expected paths without messing
     * with the real Linux system. */
    macify_init_prefix();

    /* Set MACIFY_BINARY so exec/posix_spawn shims can re-run through macify.
     * Use /proc/self/exe to get the absolute path to the macify binary. */
    {
        char exe_path[4096];
        ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (n > 0) {
            exe_path[n] = '\0';
            setenv("MACIFY_BINARY", exe_path, 1);
            if (g_verbose)
                fprintf(stderr, "macify: MACIFY_BINARY=%s\n", exe_path);
        }
    }

    /* Set PATH to macOS-style paths. This MUST be done after all dylib
     * loading (so macify can find its libraries) but before calling main
     * (so the macOS binary sees the right PATH).
     * These paths get translated to <prefix>/usr/bin, etc. by our shim.
     * This ensures macOS binaries find macOS binaries in the prefix, not
     * Linux binaries on the host. */
    setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin", 1);
    setenv("MACIFY_PATH_SET", "1", 1);

    void *stack_base = NULL;
    size_t stack_size = 0;
    /* Use environ (not envp) so any setenv() calls above are included */
    extern char **environ;
    uint64_t stack_top = setup_stack(app_argc, app_argv, environ, &stack_base, &stack_size);

    /* Register our allocated stack with the shim so pthread_get_stack*_np
     * returns the correct info for the main thread. Without this, Rust's
     * runtime reads the kernel's main-thread stack (from /proc/self/maps)
     * and crashes computing guard page addresses. */
    if (g_ndylibs > 0 && g_dylibs[0].handle) {
        void (*set_stack_info)(void *, size_t) =
            (void (*)(void *, size_t))dlsym(g_dylibs[0].handle,
                                             "__macify_set_stack_info");
        if (set_stack_info) {
            set_stack_info(stack_base, stack_size);
        }
    }

    if (g_verbose) {
        fprintf(stderr, "macify: %s entry %#lx (rsp=%#lx)\n",
                have_main ? "calling main at" : "jumping to",
                (unsigned long)g_entry_rip, (unsigned long)stack_top);
    }

    /* If LC_MAIN is present, call main() as a C function and exit with its
     * return value. Otherwise, jump to the LC_UNIXTHREAD entry point. */
    if (have_main) {
        /* Reinstall crash handler before main.
         * SA_ONSTACK is required for Go binary compatibility. */
        {
            struct sigaction sa2;
            memset(&sa2, 0, sizeof(sa2));
            sa2.sa_sigaction = crash_handler;
            sa2.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
            sigemptyset(&sa2.sa_mask);
            sigaction(SIGSEGV, &sa2, NULL);
            sigaction(SIGBUS, &sa2, NULL);
            sigaction(SIGABRT, &sa2, NULL);
            sigaction(SIGFPE,  &sa2, NULL);   /* reinstall for SIGFPE so div-by-zero
                                               * gets the full crash dump too */
        }
    /* Verify SIGSEGV handler is still installed */
    {
        struct sigaction check_sa;
        sigaction(SIGSEGV, NULL, &check_sa);
        if (check_sa.sa_sigaction != crash_handler) {
            char b[128]; int n = snprintf(b, sizeof(b), "macify: WARNING: SIGSEGV handler was overridden to %p!\n", (void*)check_sa.sa_sigaction);
            (void)write(2, b, n);
            /* Re-install our handler */
            struct sigaction reinstall_sa;
            memset(&reinstall_sa, 0, sizeof(reinstall_sa));
            reinstall_sa.sa_sigaction = crash_handler;
            reinstall_sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
            sigemptyset(&reinstall_sa.sa_mask);
            sigaction(SIGSEGV, &reinstall_sa, NULL);
            sigaction(SIGABRT, &reinstall_sa, NULL);
        }
    }
        errno = 0;
        call_main_and_exit(g_entry_rip, stack_top);
    } else {
        errno = 0;
        jump_to_entry(g_entry_rip, stack_top);
    }
}

