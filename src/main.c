#include "macify.h"

/* Usage & main */

static void usage(const char *prog) {
    fprintf(stderr,
        "Mac-ify — load and run Mach-O x86_64 binaries on Linux\n"
        "\n"
        "Usage: %s [options] <macho-binary> [args...]\n"
        "\n"
        "Options:\n"
        "  -q, --quiet         suppress loader diagnostics\n"
        "      --no-fast-path  disable immediate patching (force SIGILL slow path)\n"
        "  -h, --help          show this help\n"
        "\n", prog);
}

int main(int argc, char **argv, char **envp) {
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-q") == 0 || strcmp(argv[argi], "--quiet") == 0) {
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
                break;
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
    static char sigstack[256 * 1024] __attribute__((aligned(4096)));
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
    int pie_failed = 0;
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
                munmap(base, span);  /* free reservation; segments will MAP_FIXED */
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
                    munmap(base, span);
                    if (g_verbose) {
                        fprintf(stderr, "macify: non-PIE binary — static base unavailable, using slide=%#lx\n",
                                (unsigned long)g_slide);
                    }
                }
            } else {
                /* Static address available — unmap probe, slide stays 0 */
                munmap(probe, span);
            }
        }
    }

    /* Walk load commands. */
    uint8_t *lc = file_data + sizeof(mach_header_64);
    uint8_t *lc_end = lc + hdr->sizeofcmds;
    uint64_t main_entryoff = 0;
    int have_main = 0;

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

            /* Map macOS library names to Linux equivalents */
            void *extra1 = NULL;
            if (strstr(name, "libncurses")) {
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
            } else if (strstr(name, "libintl")) {
                /* libintl is part of glibc on Linux — no separate library */
                extra1 = NULL;
            }
            if (extra1) register_extra_handle(extra1);

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

    /* Compute entry from LC_MAIN if present. */
    if (g_entry_rip == 0 && have_main) {
        for (int i = 0; i < g_nsegments; i++) {
            if (strcmp(g_segments[i].name, "__TEXT") == 0) {
                g_entry_rip = g_segments[i].vmaddr + main_entryoff;
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
    if (g_verbose) { const char m[] = "BEFORE CHAINED\n"; write(2, m, sizeof(m)-1); }
    if (g_has_chained_fixups) {
        if (execute_chained_fixups(file_data, file_size) < 0) return 1;
    }
    if (g_verbose) { const char m[] = "AFTER CHAINED\n"; write(2, m, sizeof(m)-1); }
    /* Skip __DATA_CONST reprotect for now */
    /* Verify malloc_size GOT entry */
    {
        for (int i = 0; i < g_nsegments; i++) {
            if (strcmp(g_segments[i].name, "__DATA_CONST") == 0) {
                uint64_t *got = (uint64_t *)(g_segments[i].vmaddr + 0x2b0);
                char b[128];
                int n = snprintf(b, sizeof(b), "GOT[86] after fixups = 0x%lx\n", (unsigned long)*got);
                write(2, b, n);
                break;
            }
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
            for (int i = 0; i < 0x400 - sizeof(gs_test); i++) {
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
        if (g_verbose) { const char m[] = "CHAINED FIXUPS DONE\n"; write(2, m, sizeof(m)-1); }
        /* Clear errno before entering the macOS binary. Our shim's
         * constructor code (sigaction, dladdr, etc.) may set errno,
         * and macOS binaries expect errno to be 0 at program start. */
        errno = 0;
        call_main_and_exit(g_entry_rip, stack_top);
    } else {
        errno = 0;
        jump_to_entry(g_entry_rip, stack_top);
    }
}

