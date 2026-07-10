#include "macify.h"

/* Section type constants (used for verbose output) */
#define S_4BYTE_LITERALS                0x03
#define S_8BYTE_LITERALS                0x04
#define S_LITERAL_POINTERS              0x05
#define S_MOD_INIT_FUNC_POINTERS        0x09
#define S_MOD_TERM_FUNC_POINTERS        0x0a
#define S_COALESCED                     0x0b
#define S_GB_ZEROFILL                   0x0c
#define S_INTERPOSING                   0x0d
#define S_16BYTE_LITERALS               0x0e
#define S_DTRACE_DOF                    0x0f
#define S_LAZY_DYLIB_SYMBOL_POINTERS    0x10


loaded_segment g_segments[MAX_SEGMENTS];
int g_nsegments = 0;
uint64_t g_entry_rip = 0;

/* Text range of loaded macOS binary for SIGSEGV recovery. */
uintptr_t g_macos_text_lo = 0;
uintptr_t g_macos_text_hi = 0;

/* tls_g address for Go binaries (0 for non-Go). */
uint64_t g_tls_g_addr = 0;

/* Loaded section tracking. Sections are sub-regions of segments with
 * names like "__text", "__got", "__la_symbol_ptr". Used to restrict syscall
 * patching to __text and to locate __got/__la_symbol_ptr for binding. */


loaded_section g_sections[MAX_SECTIONS];
int g_nsections = 0;

/* __LINKEDIT / symbol table state.
 *
 * The __LINKEDIT segment contains the symbol table, string table, indirect
 * symbol table, and bind/rebase bytecodes. LC_SYMTAB and LC_DYSYMTAB give
 * file offsets into it. The indirect symbol table maps __la_symbol_ptr /
 * __got entries to symbol names via:
 *   indirectsym[section.reserved1 + entry_index] -> symtab[index]
 *   -> strtab + n_strx -> symbol name string.
 */
uint32_t g_symtab_off = 0, g_symtab_nsyms = 0;
uint32_t g_strtab_off = 0, g_strtab_size = 0;
uint32_t g_indirectsym_off = 0, g_indirectsym_count = 0;

/* Runtime config */
bool g_verbose = false;
bool g_no_fast_path = false;   /* --no-fast-path: force slow path */

/* Stats */
uint64_t g_fast_path_sites = 0;   /* patched at load time */
uint64_t g_slow_path_sites = 0;   /* patched at load time */
uint64_t g_slow_path_calls = 0;   /* invoked at runtime */
bool     g_stats_printed  = false;

/* Dynamic linking state. MAX_DYLIBS defined in macify.h */
loaded_dylib g_dylibs[MAX_DYLIBS];
int g_ndylibs = 0;

/* Extra library handles (libncurses, libz, etc.) loaded by the loader
 * for non-libSystem macOS dylibs. resolve_symbol tries these as a
 * fallback when shim/libc/libm don't have the symbol. */
#define MAX_EXTRA_HANDLES 16
void *g_extra_handles[MAX_EXTRA_HANDLES];
int g_n_extra_handles = 0;

void register_extra_handle(void *handle) {
    if (handle && g_n_extra_handles < MAX_EXTRA_HANDLES) {
        g_extra_handles[g_n_extra_handles++] = handle;
    }
}

/* Look up a symbol from a dylib, trying shim → libc → libm → extra → $-suffix strip.
 * Returns the symbol address or NULL. */
void *resolve_symbol(int ordinal_idx, const char *sym) {
    /* ordinal -1 = flat namespace: search all loaded libraries.
     * IMPORTANT: check shim FIRST, then libc/libm, then RTLD_DEFAULT.
     * This ensures our overrides (mmap, open, connect, etc.) take
     * priority over glibc's versions, which don't translate macOS flags. */
    if (ordinal_idx == -1) {
        /* Check shim → libc → libm for each dylib entry */
        for (int i = 0; i < g_ndylibs; i++) {
            void *addr = dlsym(g_dylibs[i].handle, sym);
            if (!addr && g_dylibs[i].libc_handle) addr = dlsym(g_dylibs[i].libc_handle, sym);
            if (addr) return addr;
        }
        /* Check extra handles */
        for (int i = 0; i < g_n_extra_handles; i++) {
            void *addr = dlsym(g_extra_handles[i], sym);
            if (addr) return addr;
        }
        /* Last resort: RTLD_DEFAULT (searches all loaded libraries) */
        {
            void *addr = dlsym(RTLD_DEFAULT, sym);
            if (addr) return addr;
        }
        /* Search loaded Mach-O dylibs */
        {
            extern void *macho_dylib_lookup(const char *);
            void *addr = macho_dylib_lookup(sym);
            if (addr) return addr;
        }
        /* Try stripping $-suffix for flat namespace too
         * (e.g. fdopendir$INODE64 -> fdopendir, realpath$DARWIN_EXTSN -> realpath) */
        {
            char base_sym[256];
            strncpy(base_sym, sym, 255);
            base_sym[255] = '\0';
            char *dollar = strchr(base_sym, '$');
            if (dollar) {
                *dollar = '\0';
                void *addr = dlsym(RTLD_DEFAULT, base_sym);
                if (addr) return addr;
                for (int i = 0; i < g_ndylibs; i++) {
                    addr = dlsym(g_dylibs[i].handle, base_sym);
                    if (!addr && g_dylibs[i].libc_handle) addr = dlsym(g_dylibs[i].libc_handle, base_sym);
                    if (!addr && g_dylibs[i].libm_handle) addr = dlsym(g_dylibs[i].libm_handle, base_sym);
                    if (addr) return addr;
                }
                for (int i = 0; i < g_n_extra_handles; i++) {
                    addr = dlsym(g_extra_handles[i], base_sym);
                    if (addr) return addr;
                }
            }
        }
        return NULL;
    }

    if (ordinal_idx < 0 || ordinal_idx >= g_ndylibs) return NULL;
    loaded_dylib *dy = &g_dylibs[ordinal_idx];

    /* For data symbols like 'environ', dlsym(libc_handle, ...) returns
     * libc's weak definition, which may differ from the CRT's strong
     * definition. Check RTLD_DEFAULT first to get the strong definition. */
    void *addr = NULL;
    if (strcmp(sym, "environ") == 0 || strcmp(sym, "__environ") == 0) {
        addr = dlsym(RTLD_DEFAULT, sym);
    }
    if (!addr) addr = dlsym(dy->handle, sym);
    if (!addr && dy->libc_handle) addr = dlsym(dy->libc_handle, sym);
    if (!addr && dy->libm_handle) addr = dlsym(dy->libm_handle, sym);

    /* Try extra handles (libncurses, libz, etc.) */
    if (!addr) {
        for (int i = 0; i < g_n_extra_handles; i++) {
            addr = dlsym(g_extra_handles[i], sym);
            if (addr) return addr;
        }
    }

    /* Search loaded Mach-O dylibs */
    if (!addr) {
        extern void *macho_dylib_lookup(const char *);
        addr = macho_dylib_lookup(sym);
        if (addr) return addr;
    }

    /* Try stripping $-suffix (e.g. _open$NOCANCEL -> _open) */
    if (!addr) {
        char base_sym[256];
        strncpy(base_sym, sym, 255);
        base_sym[255] = '\0';
        char *dollar = strchr(base_sym, '$');
        if (dollar) {
            *dollar = '\0';
            addr = dlsym(dy->handle, base_sym);
            if (!addr && dy->libc_handle) addr = dlsym(dy->libc_handle, base_sym);
            if (!addr && dy->libm_handle) addr = dlsym(dy->libm_handle, base_sym);
            if (!addr) {
                for (int i = 0; i < g_n_extra_handles; i++) {
                    addr = dlsym(g_extra_handles[i], base_sym);
                    if (addr) return addr;
                }
            }
        }
    }

    /* Last resort: try flat namespace (RTLD_DEFAULT) */
    if (!addr) {
        addr = dlsym(RTLD_DEFAULT, sym);
    }

    return addr;
}

/* LC_DYLD_INFO bind/rebase bytecode location (file offsets) */
uint32_t g_rebase_off = 0, g_rebase_size = 0;
uint32_t g_bind_off   = 0, g_bind_size   = 0;
uint32_t g_lazy_bind_off = 0, g_lazy_bind_size = 0;

/* Chained fixups (modern macOS format) */
uint32_t g_chained_fixups_off = 0, g_chained_fixups_size = 0;
bool g_has_chained_fixups = false;



int prot_from_macos(int macos_prot) {
    int p = 0;
    if (macos_prot & VM_PROT_READ)    p |= PROT_READ;
    if (macos_prot & VM_PROT_WRITE)   p |= PROT_WRITE;
    if (macos_prot & VM_PROT_EXECUTE) p |= PROT_EXEC;
    return p;
}

/* Find a section by segment name and section name.
 * Returns NULL if not found. Both names are compared up to 16 chars. */
loaded_section *find_section(const char *segname, const char *sectname) {
    for (int i = 0; i < g_nsections; i++) {
        if (strncmp(g_sections[i].segname, segname, 16) == 0 &&
            strncmp(g_sections[i].sectname, sectname, 16) == 0) {
            return &g_sections[i];
        }
    }
    return NULL;
}

/* Check if a section contains code (has S_ATTR_SOME_INSTRUCTIONS or
 * S_ATTR_PURE_INSTRUCTIONS set). Used to restrict syscall patching. */
bool section_is_code(const loaded_section *s) {
    if (!s) return false;
    return (s->flags & S_ATTR_SOME_INSTRUCTIONS) != 0 ||
           (s->flags & S_ATTR_PURE_INSTRUCTIONS) != 0;
}

int map_segment(segment_command_64 *seg,
                       uint8_t *file_data, size_t file_size) {
    if (g_nsegments >= MAX_SEGMENTS) {
        fprintf(stderr, "macify: too many segments (max %d)\n", MAX_SEGMENTS);
        return -1;
    }
    if (seg->vmsize == 0) return 0;

    int is_pagezero = (strcmp(seg->segname, "__PAGEZERO") == 0);

    /* Compute the slid vmaddr. For __PAGEZERO, we don't slide (it stays
     * at address 0 as a null-page guard, and we skip it anyway). */
    uint64_t slid_vmaddr = is_pagezero ? seg->vmaddr : (seg->vmaddr + g_slide);

    if (is_pagezero) {
        if (g_verbose) {
            fprintf(stderr, "macify: skipping __PAGEZERO at %#lx+%-lx\n",
                    (unsigned long)seg->vmaddr, (unsigned long)seg->vmsize);
        }
        loaded_segment *s = &g_segments[g_nsegments++];
        s->vmaddr = seg->vmaddr;  /* store static vmaddr for __PAGEZERO */
        s->vmsize = seg->vmsize;
        s->prot = PROT_NONE;
        s->target_prot = PROT_NONE;
        s->is_pagezero = 1;
        strncpy(s->name, seg->segname, 16);
        return 0;
    }

    /* Start as RWX during patching, downgrade to target prot after. */
    int initial_prot = PROT_READ | PROT_WRITE;
    if (seg->initprot & VM_PROT_EXECUTE) initial_prot |= PROT_EXEC;

    /* Use mprotect + memcpy instead of MAP_FIXED to avoid overwriting
     * other mappings (ld-linux, libc, etc.) when the macOS binary's
     * segments have large BSS sections. The reservation was already
     * made during slide computation; we just need to change protection
     * and copy data. */
    /* Round vmsize up to page size */
    size_t map_size = (seg->vmsize + 4095) & ~4095UL;

    /* Change protection from PROT_NONE (reserved) to RWX/RW */
    if (mprotect((void *)(uintptr_t)slid_vmaddr, map_size, initial_prot) != 0) {
        /* mprotect failed — the reservation might have been freed.
         * Fall back to MAP_FIXED. */
        void *r = mmap((void *)(uintptr_t)slid_vmaddr, map_size,
                       initial_prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                       -1, 0);
        if (r == MAP_FAILED) {
            fprintf(stderr, "macify: mmap segment %s at %#lx (size %#lx): %s\n",
                    seg->segname, (unsigned long)slid_vmaddr,
                    (unsigned long)map_size, strerror(errno));
            return -1;
        }
    }

    if (seg->filesize > 0) {
        if (seg->fileoff + seg->filesize > file_size) {
            fprintf(stderr, "macify: segment %s extends past EOF\n", seg->segname);
            return -1;
        }
        memcpy((void *)(uintptr_t)slid_vmaddr,
               file_data + seg->fileoff,
               seg->filesize);
    }

    /* Zero-fill the BSS part (vmsize > filesize) */
    if (seg->vmsize > seg->filesize) {
        memset((void *)(uintptr_t)(slid_vmaddr + seg->filesize), 0,
               seg->vmsize - seg->filesize);
    }

    loaded_segment *s = &g_segments[g_nsegments++];
    s->vmaddr = slid_vmaddr;  /* store the SLID vmaddr for bind/rebase/entry */
    s->vmsize = seg->vmsize;
    s->prot = initial_prot;
    s->target_prot = prot_from_macos(seg->initprot);
    s->is_pagezero = 0;
    strncpy(s->name, seg->segname, 16);

    if (g_verbose) {
        if (g_slide != 0) {
            fprintf(stderr, "macify: mapped %-16s vm=%#010lx+%-6lx (static=%#lx slide=%#lx) file=%lu+%lu prot=%d->%d\n",
                    s->name, (unsigned long)s->vmaddr, (unsigned long)s->vmsize,
                    (unsigned long)seg->vmaddr, (unsigned long)g_slide,
                    (unsigned long)seg->fileoff, (unsigned long)seg->filesize,
                    initial_prot, s->target_prot);
        } else {
            fprintf(stderr, "macify: mapped %-16s vm=%#010lx+%-6lx file=%lu+%lu prot=%d->%d\n",
                    s->name, (unsigned long)s->vmaddr, (unsigned long)s->vmsize,
                    (unsigned long)seg->fileoff, (unsigned long)seg->filesize,
                    initial_prot, s->target_prot);
        }
    }

    /* Parse sections within this segment. The section_64 structs follow
     * the segment_command_64 in the load command data. Each section is
     * 80 bytes. We store them with the slide applied to addr. */
    if (seg->nsects > 0) {
        section_64 *sects = (section_64 *)(void *)((uint8_t *)seg + sizeof(segment_command_64));
        for (uint32_t i = 0; i < seg->nsects; i++) {
            if (g_nsections >= MAX_SECTIONS) {
                fprintf(stderr, "macify: too many sections (max %d)\n", MAX_SECTIONS);
                return -1;
            }
            loaded_section *ls = &g_sections[g_nsections++];
            strncpy(ls->sectname, sects[i].sectname, 16);
            strncpy(ls->segname, sects[i].segname, 16);
            ls->addr = sects[i].addr + g_slide;  /* apply ASLR/PIE slide */
            ls->size = sects[i].size;
            ls->offset = sects[i].offset;
            ls->flags = sects[i].flags;
            ls->reserved1 = sects[i].reserved1;
            ls->reserved2 = sects[i].reserved2;

            if (g_verbose) {
                /* Show section type as a short tag */
                const char *type_str = "reg";
                switch (sects[i].flags & 0xFF) {
                    case S_REGULAR:                    type_str = "reg";    break;
                    case S_ZEROFILL:                   type_str = "zfill";  break;
                    case S_CSTRING_LITERALS:           type_str = "cstr";   break;
                    case S_4BYTE_LITERALS:             type_str = "4lit";   break;
                    case S_8BYTE_LITERALS:             type_str = "8lit";   break;
                    case S_NON_LAZY_SYMBOL_POINTERS:   type_str = "nlsym";  break;
                    case S_LAZY_SYMBOL_POINTERS:       type_str = "lsym";   break;
                    case S_SYMBOL_STUBS:               type_str = "stub";   break;
                    case S_MOD_INIT_FUNC_POINTERS:     type_str = "init";   break;
                    case S_MOD_TERM_FUNC_POINTERS:     type_str = "term";   break;
                    default:                           type_str = "?";      break;
                }
                fprintf(stderr, "macify:   section %-16s.%-16s addr=%#010lx+%-6lx type=%s flags=%#x\n",
                        ls->segname, ls->sectname,
                        (unsigned long)ls->addr, (unsigned long)ls->size,
                        type_str, sects[i].flags);
            }
        }
    }
    return 0;
}


/* Global ASLR/PIE slide (set in main.c, consumed by segment mapping
 * and fixup interpreters). */
int64_t  g_slide = 0;

/* File loading. */
uint8_t *load_file(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return NULL; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return NULL; }
    size_t size = (size_t)st.st_size;
    uint8_t *data = malloc(size);
    if (!data) { close(fd); return NULL; }
    ssize_t n = read(fd, data, size);
    close(fd);
    if (n != (ssize_t)size) {
        fprintf(stderr, "macify: short read on %s\n", path);
        free(data);
        return NULL;
    }
    *out_size = size;
    return data;
}

