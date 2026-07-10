/* macho_dylib.c — Mach-O shared library loader
 *
 * Loads Mach-O .dylib files into memory so they can be used by macOS
 * binaries. This is needed for dynamically-linked macOS binaries like
 * Ruby (libruby.4.0.dylib), Python (libpython3.x.dylib), etc.
 *
 * The loader:
 *   1. Reads the Mach-O dylib file
 *   2. Reserves memory and maps segments with a slide
 *   3. Processes rebase fixups (adjust pointers for slide)
 *   4. Processes bind fixups (resolve imported symbols)
 *   5. Extracts exported symbols from the symbol table
 *   6. Runs module initializers (__mod_init_func)
 *   7. Registers the dylib so resolve_symbol() can find its exports
 */

#include "macify.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

/* Mach-O constants not in macify.h */
#define MH_DYLIB    6
#define N_EXT       0x01
#define N_TYPE      0x0e
#define N_SECT      0x0e

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} load_command;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} linkedit_data_command;

/* Rebase opcodes (from LC_DYLD_INFO) */
#define LC_DYLD_INFO 0x22u
#define REBASE_OPCODE_DONE                             0x00
#define REBASE_OPCODE_SET_TYPE_IMM                     0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB                    0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED              0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES              0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES             0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB          0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

/* Global array of loaded Mach-O dylibs */
macho_dylib g_macho_dylibs[MAX_MACHO_DYLIBS];
int g_n_macho_dylibs = 0;

/* ── Symbol table parsing ────────────────────────────────────── */

/* Parse a Mach-O dylib's symbol table to extract exported symbols.
 * A symbol is exported if:
 *   - n_type & N_EXT (external/global)
 *   - n_type & N_TYPE == N_SECT (defined in a section)
 *   - n_desc & N_WEAK_REF is NOT set (or we include weak too)
 *   - n_value != 0 (has an address) */
static void parse_dylib_exports(macho_dylib *md, uint8_t *file_data, size_t file_size) {
    mach_header_64 *hdr = (mach_header_64 *)file_data;
    if (hdr->magic != MH_MAGIC_64) return;

    /* Find LC_SYMTAB */
    uint32_t symtab_off = 0, symtab_nsyms = 0;
    uint32_t strtab_off = 0, strtab_size = 0;
    load_command *lc = (load_command *)(file_data + sizeof(mach_header_64));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) {
            symtab_command *sc = (symtab_command *)lc;
            symtab_off = sc->symoff;
            symtab_nsyms = sc->nsyms;
            strtab_off = sc->stroff;
            strtab_size = sc->strsize;
            break;
        }
        lc = (load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    if (symtab_off == 0 || symtab_nsyms == 0) return;

    const char *strtab = (const char *)(file_data + strtab_off);
    nlist_64 *syms = (nlist_64 *)(file_data + symtab_off);

    for (uint32_t i = 0; i < symtab_nsyms && md->n_exports < MAX_DYLIB_SYMS; i++) {
        nlist_64 *nl = &syms[i];

        /* Skip undefined symbols (not defined in this dylib) */
        if ((nl->n_type & N_TYPE) != N_SECT) continue;
        /* Skip non-external (local) symbols */
        if (!(nl->n_type & N_EXT)) continue;
        /* Skip symbols with no value */
        if (nl->n_value == 0) continue;

        /* Get symbol name */
        if (nl->n_strx >= strtab_size) continue;
        const char *name = strtab + nl->n_strx;
        if (!name[0]) continue;

        /* Strip leading underscore (macOS convention) */
        if (name[0] == '_') name++;

        /* Store: name → address (with slide applied) */
        strncpy(md->exports[md->n_exports].name, name, 127);
        md->exports[md->n_exports].name[127] = '\0';
        md->exports[md->n_exports].addr = (void *)(uintptr_t)(nl->n_value + md->slide);
        md->n_exports++;
    }
}

/* ── Segment mapping ────────────────────────────────────────── */

/* Map a Mach-O dylib's segments into memory with a slide.
 * Returns the slide value, or 0 on failure. */
static int64_t map_dylib_segments(uint8_t *file_data, size_t file_size, macho_dylib *md) {
    mach_header_64 *hdr = (mach_header_64 *)file_data;
    if (hdr->magic != MH_MAGIC_64) return -1;

    /* First pass: compute total address span */
    uint64_t lo = UINT64_MAX, hi = 0;
    load_command *lc = (load_command *)(file_data + sizeof(mach_header_64));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            segment_command_64 *seg = (segment_command_64 *)lc;
            if (seg->vmsize > 0 && !(seg->vmaddr == 0 && seg->vmsize > 0x80000000)) {
                if (seg->vmaddr < lo) lo = seg->vmaddr;
                if (seg->vmaddr + seg->vmsize > hi) hi = seg->vmaddr + seg->vmsize;
            }
        }
        lc = (load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    if (lo == UINT64_MAX) return -1;
    uint64_t span = hi - lo;

    /* Reserve memory for the dylib (let kernel pick address) */
    void *base = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return -1;

    int64_t slide = (int64_t)(uintptr_t)base - (int64_t)lo;

    /* Second pass: map each segment using memcpy into the reserved region */
    lc = (load_command *)(file_data + sizeof(mach_header_64));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            segment_command_64 *seg = (segment_command_64 *)lc;
            if (seg->vmsize == 0) continue;
            /* Skip __PAGEZERO */
            if (seg->vmaddr == 0 && seg->vmsize >= 0x80000000) continue;

            uint64_t target = seg->vmaddr + slide;
            int prot = 0;
            if (seg->initprot & VM_PROT_READ)  prot |= PROT_READ;
            if (seg->initprot & VM_PROT_WRITE) prot |= PROT_WRITE;
            if (seg->initprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;

            /* The region was already reserved with PROT_NONE by the initial mmap.
             * Change protection to read/write so we can copy data in. */
            size_t map_size = seg->vmsize;
            /* Round up to page size */
            map_size = (map_size + 4095) & ~4095UL;

            mprotect((void *)(uintptr_t)target, map_size, PROT_READ | PROT_WRITE);

            /* Copy file data into the mapped region */
            if (seg->filesize > 0) {
                memcpy((void *)(uintptr_t)target, file_data + seg->fileoff, seg->filesize);
            }

            /* Zero-fill the remaining (BSS) part */
            if (seg->vmsize > seg->filesize) {
                memset((void *)(uintptr_t)(target + seg->filesize), 0,
                       seg->vmsize - seg->filesize);
            }

            /* Set correct protection.
             * For __DATA_CONST: macOS makes this read-only after fixups.
             * We keep it writable during fixup processing (GOT resolution
             * needs to write to it), then make it read-only AFTER all
             * fixups are done. For now, keep it writable — the GOT
             * resolution happens after segment mapping. */
            mprotect((void *)(uintptr_t)target, map_size, prot);
        }
        lc = (load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    return slide;
}

/* ── Dylib segment tracking ─────────────────────────────────── */

/* Track the dylib's own segments for rebase processing */
typedef struct {
    uint64_t vmaddr;    /* static VM address */
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
} dylib_segment;

#define MAX_DYLIB_SEGS 16

/* Process rebase opcodes (LC_DYLD_INFO format) for a dylib.
 * Adjusts internal pointers by the slide. */
static void process_dylib_rebases(uint8_t *file_data, size_t file_size,
                                  int64_t slide,
                                  uint32_t rebase_off, uint32_t rebase_size,
                                  dylib_segment *segs, int nsegs) {
    if (rebase_off == 0 || rebase_size == 0) return;

    uint8_t *p = file_data + rebase_off;
    uint8_t *end = p + rebase_size;

    int seg_index = -1;
    uint64_t seg_offset = 0;
    uint8_t type = 0;

    while (p < end) {
        uint8_t op = *p++;
        uint8_t imm = op & 0x0F;
        op &= 0xF0;

        switch (op) {
            case REBASE_OPCODE_DONE:
                return;
            case REBASE_OPCODE_SET_TYPE_IMM:
                type = imm;
                break;
            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_index = imm;
                seg_offset = read_uleb128((const uint8_t **)&p, end);
                break;
            case REBASE_OPCODE_ADD_ADDR_ULEB:
                seg_offset += read_uleb128((const uint8_t **)&p, end);
                break;
            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                seg_offset += (uint64_t)imm * sizeof(uint64_t);
                break;
            case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                for (int i = 0; i < imm; i++) {
                    if (seg_index >= 0 && seg_index < nsegs) {
                        uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                        uint64_t *ptr = (uint64_t *)(uintptr_t)target;
                        *ptr += slide;
                    }
                    seg_offset += sizeof(uint64_t);
                }
                break;
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
                uint64_t count = read_uleb128((const uint8_t **)&p, end);
                for (uint64_t i = 0; i < count; i++) {
                    if (seg_index >= 0 && seg_index < nsegs) {
                        uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                        uint64_t *ptr = (uint64_t *)(uintptr_t)target;
                        *ptr += slide;
                    }
                    seg_offset += sizeof(uint64_t);
                }
                break;
            }
            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                if (seg_index >= 0 && seg_index < nsegs) {
                    uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                    uint64_t *ptr = (uint64_t *)(uintptr_t)target;
                    *ptr += slide;
                }
                seg_offset += sizeof(uint64_t) + read_uleb128((const uint8_t **)&p, end);
                break;
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128((const uint8_t **)&p, end);
                uint64_t skip = read_uleb128((const uint8_t **)&p, end);
                for (uint64_t i = 0; i < count; i++) {
                    if (seg_index >= 0 && seg_index < nsegs) {
                        uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                        uint64_t *ptr = (uint64_t *)(uintptr_t)target;
                        *ptr += slide;
                    }
                    seg_offset += skip + sizeof(uint64_t);
                }
                break;
            }
            default:
                return;
        }
    }
}

/* Process chained fixups for a dylib.
 * Chained fixups use a linked-list format within each page.
 * Each fixup is either a REBASE (add slide) or BIND (resolve symbol). */
static void process_dylib_chained_fixups(uint8_t *file_data, size_t file_size,
                                         int64_t slide,
                                         uint32_t fixups_off, uint32_t fixups_size,
                                         dylib_segment *segs, int nsegs) {
    if (fixups_off == 0 || fixups_size == 0) return;
    if (fixups_off + fixups_size > file_size) return;

    uint8_t *fixup_data = file_data + fixups_off;
    dyld_chained_fixups_header *hdr = (dyld_chained_fixups_header *)fixup_data;
    if (hdr->fixups_version != 0) return;

    /* Parse starts_in_image */
    uint8_t *starts_base = fixup_data + hdr->starts_offset;
    uint32_t n_image_segs = *(uint32_t *)starts_base;
    uint32_t *seg_offsets = (uint32_t *)(starts_base + 4);

    /* Parse imports */
    uint8_t *imports_base = fixup_data + hdr->imports_offset;
    uint8_t *symbols_base = hdr->symbols_offset ? (fixup_data + hdr->symbols_offset) : NULL;

    for (uint32_t si = 0; si < n_image_segs && si < (uint32_t)nsegs; si++) {
        if (seg_offsets[si] == 0) continue;

        uint8_t *seg_starts = starts_base + seg_offsets[si];
        uint32_t seg_size = *(uint32_t *)seg_starts;
        uint16_t page_size = *(uint16_t *)(seg_starts + 4);
        uint16_t ptr_format = *(uint16_t *)(seg_starts + 6);
        uint64_t seg_offset = *(uint64_t *)(seg_starts + 8);
        uint16_t page_count = *(uint16_t *)(seg_starts + 20);
        uint16_t *page_starts = (uint16_t *)(seg_starts + 22);

        (void)seg_size;

        for (uint16_t pi = 0; pi < page_count; pi++) {
            uint16_t page_start = page_starts[pi];
            if (page_start == 0xFFFF) continue;  /* DYLD_CHAINED_PTR_START_NONE */
            if (page_start == 0 && page_count > 1 && pi > 0) continue;  /* skip empty pages */

            /* Page base in mapped memory */
            uint8_t *page_base = (uint8_t *)(uintptr_t)(segs[si].vmaddr + slide) +
                                 (uint64_t)pi * page_size;
            uint8_t *page_end = page_base + page_size;
            if (page_end > (uint8_t *)(uintptr_t)(segs[si].vmaddr + slide) + segs[si].vmsize)
                page_end = (uint8_t *)(uintptr_t)(segs[si].vmaddr + slide) + segs[si].vmsize;

            uint8_t *chain_ptr = page_base + page_start;
            if (chain_ptr + 8 > page_end) continue;

            int chain_iter = 0;
            while (chain_iter < 16384) {
                uint64_t value = *(uint64_t *)chain_ptr;
                bool is_bind = (value >> 63) & 1;
                uint32_t next = (value >> 51) & 0xFFF;  /* bits 48-59 */

                if (is_bind) {
                    uint32_t ordinal = value & 0xFFFF;
                    uint32_t addend = (value >> 16) & 0xFFFF;

                    if (ordinal < hdr->imports_count) {
                        /* DYLD_CHAINED_IMPORT format (4 bytes per import):
                         * bits 0-7: lib_ordinal, bit 8: weak, bits 9-31: name_offset */
                        uint32_t imp_raw = *(uint32_t *)(imports_base + ordinal * 4);
                        int lib_ordinal = imp_raw & 0xFF;
                        uint32_t name_off = (imp_raw >> 9) & 0x7FFFFF;
                        const char *sym_name = symbols_base ?
                            (const char *)(symbols_base + name_off) : "";
                        const char *sym = sym_name;
                        if (sym[0] == '_') sym++;

                        void *addr;
                        if (lib_ordinal == 0 || lib_ordinal >= 0xFB)
                            addr = resolve_symbol(-1, sym);
                        else
                            addr = resolve_symbol(lib_ordinal - 1, sym);

                        if (addr) {
                            *(uint64_t *)chain_ptr = (uint64_t)(uintptr_t)addr + addend;
                        }
                    }
                } else {
                    /* REBASE: target is offset from image base, add slide */
                    uint64_t target = value & 0xFFFFFFFFF;  /* 36 bits */
                    uint8_t high8 = (value >> 36) & 0xFF;
                    uint64_t full_target = ((uint64_t)high8 << 36) | target;
                    /* For non-PIE dylibs, vmaddr=0, so full_target is the offset */
                    *(uint64_t *)chain_ptr = full_target + slide;
                }

                if (next == 0) break;
                chain_ptr += next * 4;
                if (chain_ptr + 8 > page_end) break;
                chain_iter++;
            }
        }
    }
}

/* ── Bind fixup processing for dylibs ────────────────────────── */

/* Bind opcodes (same as main binary) */
#define BIND_OPCODE_DONE                             0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    0x40
#define BIND_OPCODE_SET_TYPE_IMM                     0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                  0x60
#define BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB 0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                    0x80
#define BIND_OPCODE_DO_BIND                          0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xC0
#define BIND_TYPE_POINTER 1

/* Process bind opcodes for a dylib.
 * Resolves the dylib's external imports against shim/libc/libm. */
static void process_dylib_binds(uint8_t *file_data, size_t file_size,
                                int64_t slide,
                                uint32_t bind_off, uint32_t bind_size,
                                dylib_segment *segs, int nsegs) {
    if (bind_off == 0 || bind_size == 0) return;
    if (bind_off + bind_size > file_size) return;

    uint8_t *p = file_data + bind_off;
    uint8_t *end = p + bind_size;

    int seg_index = -1;
    uint64_t seg_offset = 0;
    uint32_t type = 0;
    int lib_ordinal = 0;
    char sym_name[256] = "";
    int64_t addend = 0;

    while (p < end) {
        uint8_t op = *p++;
        uint8_t imm = op & 0x0F;
        op &= 0xF0;

        switch (op) {
            case BIND_OPCODE_DONE:
                return;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                lib_ordinal = imm;
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                lib_ordinal = (int)read_uleb128((const uint8_t **)&p, end);
                break;

            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                lib_ordinal = imm ? (int)(imm | 0xF0) : 0;
                break;

            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                size_t i = 0;
                while (p < end && *p != 0 && i < sizeof(sym_name) - 1) {
                    sym_name[i++] = *p++;
                }
                sym_name[i] = '\0';
                if (p < end) p++; /* skip null terminator */
                break;
            }

            case BIND_OPCODE_SET_TYPE_IMM:
                type = imm;
                break;

            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128((const uint8_t **)&p, end);
                break;

            case BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB:
                seg_index = imm;
                seg_offset = read_uleb128((const uint8_t **)&p, end);
                break;

            case BIND_OPCODE_ADD_ADDR_ULEB:
                seg_offset += read_uleb128((const uint8_t **)&p, end);
                break;

            case BIND_OPCODE_DO_BIND:
                if (seg_index >= 0 && seg_index < nsegs) {
                    uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                    const char *sym = sym_name;
                    if (sym[0] == '_') sym++;

                    /* Resolve symbol: use flat namespace (search all) */
                    void *addr = resolve_symbol(-1, sym);
                    if (addr) {
                        *(uint64_t *)(uintptr_t)target = (uint64_t)(uintptr_t)addr + addend;
                        if (getenv("MACIFY_TRACE_FIXUPS") && g_verbose)
                            fprintf(stderr, "macify: dylib bind %s -> %p at 0x%lx\n",
                                    sym, addr, (unsigned long)target);
                    } else {
                        /* Stub unresolved symbols */
                        extern long macify_unresolved_stub(void);
                        *(uint64_t *)(uintptr_t)target = (uint64_t)(uintptr_t)macify_unresolved_stub;
                        if (g_verbose)
                            fprintf(stderr, "macify: dylib bind STUBBED: %s\n", sym);
                    }
                    seg_offset += sizeof(uint64_t);
                }
                break;

            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                if (seg_index >= 0 && seg_index < nsegs) {
                    uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                    const char *sym = sym_name;
                    if (sym[0] == '_') sym++;
                    void *addr = resolve_symbol(-1, sym);
                    if (addr) {
                        *(uint64_t *)(uintptr_t)target = (uint64_t)(uintptr_t)addr + addend;
                    }
                    seg_offset += sizeof(uint64_t) + read_uleb128((const uint8_t **)&p, end);
                }
                break;

            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                if (seg_index >= 0 && seg_index < nsegs) {
                    uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                    const char *sym = sym_name;
                    if (sym[0] == '_') sym++;
                    void *addr = resolve_symbol(-1, sym);
                    if (addr) {
                        *(uint64_t *)(uintptr_t)target = (uint64_t)(uintptr_t)addr + addend;
                    }
                    seg_offset += (uint64_t)imm * sizeof(uint64_t) + sizeof(uint64_t);
                }
                break;

            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128((const uint8_t **)&p, end);
                uint64_t skip = read_uleb128((const uint8_t **)&p, end);
                for (uint64_t i = 0; i < count; i++) {
                    if (seg_index >= 0 && seg_index < nsegs) {
                        uint64_t target = segs[seg_index].vmaddr + seg_offset + slide;
                        const char *sym = sym_name;
                        if (sym[0] == '_') sym++;
                        void *addr = resolve_symbol(-1, sym);
                        if (addr) {
                            *(uint64_t *)(uintptr_t)target = (uint64_t)(uintptr_t)addr + addend;
                        }
                    }
                    seg_offset += skip + sizeof(uint64_t);
                }
                break;
            }

            default:
                /* Unknown opcode — stop to avoid corrupting state */
                return;
        }
    }
}

/* ── Public API ─────────────────────────────────────────────── */

/* Load a Mach-O dylib into memory and register its symbols.
 * Returns 0 on success, -1 on failure. */
int macho_load_dylib(const char *path) {
    if (g_n_macho_dylibs >= MAX_MACHO_DYLIBS) {
        if (g_verbose)
            fprintf(stderr, "macify: too many Mach-O dylibs (max %d)\n", MAX_MACHO_DYLIBS);
        return -1;
    }

    /* Check if already loaded */
    for (int i = 0; i < g_n_macho_dylibs; i++) {
        if (strcmp(g_macho_dylibs[i].name, path) == 0)
            return 0;  /* already loaded */
    }

    /* Read the file */
    size_t file_size;
    uint8_t *file_data = load_file(path, &file_size);
    if (!file_data) {
        if (g_verbose)
            fprintf(stderr, "macify: failed to load dylib: %s\n", path);
        return -1;
    }

    /* Verify it's a Mach-O 64-bit file */
    mach_header_64 *hdr = (mach_header_64 *)file_data;
    if (hdr->magic != MH_MAGIC_64) {
        if (g_verbose)
            fprintf(stderr, "macify: not a Mach-O 64-bit file: %s\n", path);
        free(file_data);
        return -1;
    }

    /* Verify it's a dylib (MH_DYLIB) */
    if (hdr->filetype != MH_DYLIB) {
        if (g_verbose)
            fprintf(stderr, "macify: not a dylib (filetype=%d): %s\n", hdr->filetype, path);
        free(file_data);
        return -1;
    }

    if (g_verbose)
        fprintf(stderr, "macify: loading Mach-O dylib: %s (%zu bytes)\n", path, file_size);

    /* Register the dylib */
    macho_dylib *md = &g_macho_dylibs[g_n_macho_dylibs];
    memset(md, 0, sizeof(*md));
    strncpy(md->name, path, 255);
    md->file_data = file_data;
    md->file_size = file_size;

    /* Map segments */
    int64_t slide = map_dylib_segments(file_data, file_size, md);
    if (slide < 0) {
        if (g_verbose)
            fprintf(stderr, "macify: failed to map dylib segments: %s\n", path);
        free(file_data);
        return -1;
    }
    md->slide = slide;

    if (g_verbose)
        fprintf(stderr, "macify: dylib %s mapped at slide=0x%lx\n", path, (unsigned long)slide);

    /* Collect dylib's own segments for rebase processing */
    dylib_segment dsegs[MAX_DYLIB_SEGS];
    int ndsegs = 0;
    load_command *lc = (load_command *)(file_data + sizeof(mach_header_64));
    uint32_t rebase_off = 0, rebase_size = 0;
    uint32_t chained_off = 0, chained_size = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            segment_command_64 *seg = (segment_command_64 *)lc;
            if (seg->vmsize > 0 && ndsegs < MAX_DYLIB_SEGS) {
                dsegs[ndsegs].vmaddr = seg->vmaddr;
                dsegs[ndsegs].vmsize = seg->vmsize;
                dsegs[ndsegs].fileoff = seg->fileoff;
                dsegs[ndsegs].filesize = seg->filesize;
                ndsegs++;
            }
        } else if (lc->cmd == LC_DYLD_INFO_ONLY || lc->cmd == LC_DYLD_INFO) {
            dyld_info_command *di = (dyld_info_command *)lc;
            rebase_off = di->rebase_off;
            rebase_size = di->rebase_size;
        } else if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
            linkedit_data_command *ld = (linkedit_data_command *)lc;
            chained_off = ld->dataoff;
            chained_size = ld->datasize;
        }
        lc = (load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    /* Apply rebase fixups (LC_DYLD_INFO format) */
    if (rebase_off > 0 && rebase_size > 0) {
        process_dylib_rebases(file_data, file_size, slide,
                              rebase_off, rebase_size, dsegs, ndsegs);
        if (g_verbose)
            fprintf(stderr, "macify: dylib %s: %u rebase bytes processed\n", path, rebase_size);
    }

    /* Apply chained fixups */
    if (chained_off > 0 && chained_size > 0) {
        process_dylib_chained_fixups(file_data, file_size, slide,
                                     chained_off, chained_size, dsegs, ndsegs);
        if (g_verbose)
            fprintf(stderr, "macify: dylib %s: chained fixups processed\n", path);
    }

    /* Apply bind fixups (LC_DYLD_INFO format) — resolve the dylib's
     * own external imports (e.g. _pthread_create, _malloc, etc.)
     * against the already-loaded shim/libc/libm libraries.
     * Also process lazy bind opcodes (resolved on first call). */
    {
        load_command *lc2 = (load_command *)(file_data + sizeof(mach_header_64));
        uint32_t bind_off2 = 0, bind_size2 = 0;
        uint32_t lazy_off2 = 0, lazy_size2 = 0;
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            if (lc2->cmd == LC_DYLD_INFO_ONLY || lc2->cmd == LC_DYLD_INFO) {
                dyld_info_command *di = (dyld_info_command *)lc2;
                bind_off2 = di->bind_off;
                bind_size2 = di->bind_size;
                lazy_off2 = di->lazy_bind_off;
                lazy_size2 = di->lazy_bind_size;
                break;
            }
            lc2 = (load_command *)((uint8_t *)lc2 + lc2->cmdsize);
        }
        if (bind_off2 > 0 && bind_size2 > 0) {
            process_dylib_binds(file_data, file_size, slide,
                                bind_off2, bind_size2, dsegs, ndsegs);
            if (g_verbose)
                fprintf(stderr, "macify: dylib %s: %u bind bytes processed\n", path, bind_size2);
        }
        if (lazy_off2 > 0 && lazy_size2 > 0) {
            process_dylib_binds(file_data, file_size, slide,
                                lazy_off2, lazy_size2, dsegs, ndsegs);
            if (g_verbose)
                fprintf(stderr, "macify: dylib %s: %u lazy bind bytes processed\n", path, lazy_size2);
        }
    }

    /* Parse the dylib's exported symbol table */
    parse_dylib_exports(md, file_data, file_size);

    /* Resolve __la_symbol_ptr and __got entries using the indirect symbol table.
     * First pass: find LC_SYMTAB and LC_DYSYMTAB to get table offsets.
     * Second pass: find __la_symbol_ptr and __got sections and resolve them. */
    {
        load_command *lc3 = (load_command *)(file_data + sizeof(mach_header_64));
        uint32_t symtab_off3 = 0, symtab_nsyms3 = 0;
        uint32_t strtab_off3 = 0, strtab_size3 = 0;
        uint32_t indirectsym_off3 = 0;

        /* First pass: get table offsets */
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            if (lc3->cmd == LC_SYMTAB) {
                symtab_command *sc = (symtab_command *)lc3;
                symtab_off3 = sc->symoff;
                symtab_nsyms3 = sc->nsyms;
                strtab_off3 = sc->stroff;
                strtab_size3 = sc->strsize;
            } else if (lc3->cmd == LC_DYSYMTAB) {
                dysymtab_command *dc = (dysymtab_command *)lc3;
                indirectsym_off3 = dc->indirectsymoff;
            }
            lc3 = (load_command *)((uint8_t *)lc3 + lc3->cmdsize);
        }

        /* Second pass: resolve sections */
        if (indirectsym_off3 > 0 && symtab_off3 > 0 && strtab_off3 > 0) {
            lc3 = (load_command *)(file_data + sizeof(mach_header_64));
            for (uint32_t i = 0; i < hdr->ncmds; i++) {
                if (lc3->cmd == LC_SEGMENT_64) {
                    segment_command_64 *seg = (segment_command_64 *)lc3;
                    section_64 *sects = (section_64 *)((uint8_t *)lc3 + sizeof(segment_command_64));
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        section_64 *s = &sects[j];
                        uint32_t sec_type = s->flags & 0xff;

                        /* Resolve S_LAZY_SYMBOL_POINTERS (7) and S_NON_LAZY_SYMBOL_POINTERS (6) */
                        if ((sec_type == 7 || sec_type == 6) && s->reserved1 > 0) {
                            uint32_t start_idx = s->reserved1;
                            uint32_t n_entries = s->size / 8;
                            if (g_verbose)
                                fprintf(stderr, "macify: dylib section %s.%s type=%u addr=0x%lx size=%lu r1=%u n_entries=%u\n",
                                        seg->segname, s->sectname, sec_type,
                                        (unsigned long)s->addr, (unsigned long)s->size,
                                        s->reserved1, n_entries);
                            uint32_t *indirect = (uint32_t *)(file_data + indirectsym_off3);
                            const char *strtab = (const char *)(file_data + strtab_off3);
                            nlist_64 *syms = (nlist_64 *)(file_data + symtab_off3);
                            uint64_t sec_base = s->addr + slide;
                            int resolved = 0;

                            for (uint32_t k = 0; k < n_entries; k++) {
                                uint32_t sym_idx = indirect[start_idx + k];
                                if (sym_idx & 0x80000000) continue;
                                if (sym_idx >= symtab_nsyms3) continue;
                                nlist_64 *nl = &syms[sym_idx];
                                if (nl->n_strx >= strtab_size3) continue;
                                const char *name = strtab + nl->n_strx;
                                if (name[0] == '_') name++;
                                void *addr = resolve_symbol(-1, name);
                                if (addr) {
                                    *(uint64_t *)(uintptr_t)(sec_base + k * 8) = (uint64_t)(uintptr_t)addr;
                                    resolved++;
                                } else if (g_verbose) {
                                    fprintf(stderr, "macify: dylib UNRESOLVED %s.%s[%u]: %s\n",
                                            seg->segname, s->sectname, k, name);
                                }
                            }
                            if (g_verbose && resolved > 0)
                                fprintf(stderr, "macify: dylib %s: %d/%d %s resolved\n",
                                        path, resolved, n_entries,
                                        sec_type == 7 ? "la_symbol_ptr" : "GOT");
                        }
                    }
                }
                lc3 = (load_command *)((uint8_t *)lc3 + lc3->cmdsize);
            }
        }
    }

    if (g_verbose)
        fprintf(stderr, "macify: dylib %s: %d exported symbols\n", path, md->n_exports);

    g_n_macho_dylibs++;
    return 0;
}

/* Look up a symbol in loaded Mach-O dylibs.
 * Returns the symbol address or NULL. */
void *macho_dylib_lookup(const char *sym) {
    for (int i = 0; i < g_n_macho_dylibs; i++) {
        macho_dylib *md = &g_macho_dylibs[i];
        for (int j = 0; j < md->n_exports; j++) {
            if (strcmp(md->exports[j].name, sym) == 0) {
                return md->exports[j].addr;
            }
        }
    }
    return NULL;
}
