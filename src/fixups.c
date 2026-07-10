#include "macify.h"
#include <errno.h>

/* Stub function for unresolved macOS symbols.
 * Returns -1 with errno=ENOSYS. Safe for most functions that
 * return int/ssize_t/void*. Not safe for functions returning
 * pointers (returns -1 cast to pointer). */
long macify_unresolved_stub(void) {
    errno = ENOSYS;
    return -1;
}

/* ULEB128 / SLEB128 readers — used by LC_DYLD_INFO bind/rebase bytecode. */

uint64_t read_uleb128(const uint8_t **p, const uint8_t *end) {
    uint64_t result = 0;
    int shift = 0;
    while (*p < end) {
        uint8_t byte = *(*p)++;
        result |= (uint64_t)(byte & 0x7f) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    return result;
}

int64_t read_sleb128(const uint8_t **p, const uint8_t *end) {
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    while (*p < end) {
        byte = *(*p)++;
        result |= (int64_t)(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    if (shift < 64 && (byte & 0x40)) {
        result |= -((int64_t)1 << shift);
    }
    return result;
}


/* Bind opcode interpreter.
 *
 * Parses and executes the LC_DYLD_INFO bind bytecode. For each
 * BIND_OPCODE_DO_BIND, resolves the symbol from the appropriate
 * dylib and writes its address to the target location (typically
 * a GOT entry in __DATA).
 *
 * macOS symbols have a leading underscore (e.g. "_write") which we
 * strip before dlsym lookup. Bind opcodes (from dyld source):
 *   0x00 DONE                0x50 SET_TYPE_IMM
 *   0x10 SET_DYLIB_ORD_IMM   0x60 SET_ADDEND_SLEB
 *   0x20 SET_DYLIB_ORD_ULEB  0x70 SET_SEG_RELATIVE_OFF_ULEB
 *   0x30 SET_DYLIB_SPECIAL   0x80 ADD_ADDR_ULEB
 *   0x40 SET_SYMBOL_TRAILING 0x90 DO_BIND
 *   0xA0 DO_BIND_ADD_ADDR    0xB0 DO_BIND_ADD_ADDR_IMM_SCALED
 *   0xC0 DO_BIND_ULEB_TIMES_SKIPPING_ULEB
 */

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

int execute_binds(uint8_t *file_data, size_t file_size) {
    if (g_bind_size == 0) return 0;
    if (g_bind_off + g_bind_size > file_size) {
        fprintf(stderr, "macify: bind opcodes extend past EOF\n");
        return -1;
    }

    const uint8_t *p = file_data + g_bind_off;
    const uint8_t *end = p + g_bind_size;

    int ordinal = 0;
    char symbol_name[256];
    symbol_name[0] = '\0';
    int type = BIND_TYPE_POINTER;  /* default type, as per dyld convention */
    int64_t addend = 0;
    uint64_t seg_offset = 0;
    int seg_index = 0;

    while (p < end) {
        uint8_t op = *p++;
        uint8_t imm = op & 0x0F;
        op &= 0xF0;

        switch (op) {
            case BIND_OPCODE_DONE:
                /* In lazy bind bytecodes, there can be multiple DONE-separated
                 * sequences (one per lazy symbol). If there's more data, reset
                 * state and continue. If we're at the end, return.
                 *
                 * Note: type, ordinal, and addend PERSIST across DONE boundaries
                 * in real dyld. Only seg_offset/seg_index are implicitly reset
                 * by the next SET_SEGMENT_RELATIVE_OFFSET opcode. */
                if (p >= end) return 0;
                /* Don't reset type/ordinal/addend — they persist */
                symbol_name[0] = '\0';
                seg_offset = 0;
                seg_index = 0;
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                ordinal = imm;
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                ordinal = (int)read_uleb128(&p, end);
                break;

            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                ordinal = imm ? (int8_t)(imm | 0xF0) : 0;
                break;

            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                int flags = imm;
                (void)flags;
                const uint8_t *str_start = p;
                while (p < end && *p != '\0') p++;
                if (p >= end) {
                    fprintf(stderr, "macify: symbol name truncated in bind opcodes\n");
                    return -1;
                }
                p++; /* skip null terminator */
                size_t len = (size_t)(p - str_start);
                if (len >= sizeof(symbol_name)) len = sizeof(symbol_name) - 1;
                memcpy(symbol_name, str_start, len);
                symbol_name[len] = '\0';
                break;
            }

            case BIND_OPCODE_SET_TYPE_IMM:
                type = imm;
                break;

            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128(&p, end);
                break;

            case BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB:
                seg_index = imm;
                seg_offset = read_uleb128(&p, end);
                break;

            case BIND_OPCODE_ADD_ADDR_ULEB:
                seg_offset += read_uleb128(&p, end);
                break;

            case BIND_OPCODE_DO_BIND:
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
                /* Resolve symbol from dylib */
                if (ordinal < 1 || ordinal > g_ndylibs) {
                    fprintf(stderr, "macify: bind references invalid ordinal %d\n", ordinal);
                    return -1;
                }

                /* Strip leading underscore (macOS C convention) */
                const char *sym = symbol_name;
                if (sym[0] == '_') sym++;

                /* Use resolve_symbol which checks shim → libc → libm →
                 * extra handles (libz, libncurses, etc.) → $-suffix strip */
                void *addr = resolve_symbol(ordinal - 1, sym);
                if (!addr) {
                    /* For unresolved symbols, provide a stub that returns -1/NULL. */
                    extern long macify_unresolved_stub(void);
                    addr = (void *)macify_unresolved_stub;
                    if (getenv("MACIFY_VERBOSE")) {
                        fprintf(stderr, "macify: stubbing unresolved symbol '%s' from %s\n",
                                sym, g_dylibs[ordinal - 1].name);
                    }
                }

                /* Compute target address */
                if (seg_index < 0 || seg_index >= g_nsegments) {
                    fprintf(stderr, "macify: bind references invalid segment %d\n", seg_index);
                    return -1;
                }
                uint64_t target = g_segments[seg_index].vmaddr + seg_offset;

                if (type == BIND_TYPE_POINTER) {
                    *(uint64_t *)(uintptr_t)target =
                        (uint64_t)(uintptr_t)addr + (uint64_t)addend;
                } else {
                    fprintf(stderr, "macify: unsupported bind type %d\n", type);
                    return -1;
                }

                if (g_verbose) {
                    if (g_verbose) fprintf(stderr, "macify: bound %-16s from %-24s at %#lx -> %#lx\n",
                            symbol_name, g_dylibs[ordinal - 1].name,
                            (unsigned long)target, (unsigned long)(uintptr_t)addr);
                }

                /* Advance to next slot */
                seg_offset += 8;
                if (op == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) {
                    seg_offset += read_uleb128(&p, end);
                } else if (op == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED) {
                    seg_offset += (uint64_t)imm * 8;
                }
                break;
            }

            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(&p, end);
                uint64_t skip = read_uleb128(&p, end);
                if (g_verbose) {
                    if (g_verbose) fprintf(stderr, "macify: DO_BIND_ULEB_TIMES_SKIPPING_ULEB sym=%s count=%lu skip=%lu\n",
                            symbol_name, (unsigned long)count, (unsigned long)skip);
                }
                for (uint64_t i = 0; i < count; i++) {
                    /* Re-resolve same symbol at each slot */
                    if (ordinal < 1 || ordinal > g_ndylibs) return -1;
                    const char *sym = symbol_name;
                    if (sym[0] == '_') sym++;
                    void *addr = resolve_symbol(ordinal - 1, sym);
                    if (!addr) {
                        extern long macify_unresolved_stub(void);
                        addr = (void *)macify_unresolved_stub;
                    }

                    uint64_t target = g_segments[seg_index].vmaddr + seg_offset;
                    *(uint64_t *)(uintptr_t)target = (uint64_t)(uintptr_t)addr + (uint64_t)addend;
                    if (g_verbose) {
                        if (g_verbose) fprintf(stderr, "macify:   bound[%lu] %s at %#lx -> %#lx\n",
                                (unsigned long)i, symbol_name,
                                (unsigned long)target, (unsigned long)(uintptr_t)addr);
                    }
                    seg_offset += 8 + skip;
                }
                break;
            }

            default:
                fprintf(stderr, "macify: unknown bind opcode 0x%02x\n", op | imm);
                return -1;
        }
    }
    return 0;
}


/* Rebase opcode interpreter.
 *
 * Rebases are needed when a binary has internal pointers (e.g., a
 * pointer in __DATA that points to __TEXT). The linker stores these
 * as relative offsets; dyld adds the "slide" (load address minus
 * static vmaddr) to make them absolute.
 *
 * Rebase opcodes (from dyld source):
 *   0x00 DONE                          0x50 DO_REBASE_IMM_TIMES
 *   0x10 SET_TYPE_IMM                  0x60 DO_REBASE_ULEB_TIMES
 *   0x20 SET_SEG_RELATIVE_OFF_ULEB     0x70 DO_REBASE_ADD_ADDR_ULEB
 *   0x30 ADD_ADDR_ULEB                 0x80 DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
 *   0x40 ADD_ADDR_IMM_SCALED
 *
 * Rebase types: 1=POINTER_64  2=TEXT_ABSOLUTE32  3=TEXT_PCREL32
 */

#define REBASE_OPCODE_DONE                              0x00
#define REBASE_OPCODE_SET_TYPE_IMM                      0x10
#define REBASE_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB  0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB                     0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED               0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES               0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES              0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB           0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

#define REBASE_TYPE_POINTER 1

int execute_rebases(uint8_t *file_data, size_t file_size) {
    if (g_rebase_size == 0) return 0;
    if (g_rebase_off + g_rebase_size > file_size) {
        fprintf(stderr, "macify: rebase opcodes extend past EOF\n");
        return -1;
    }

    const uint8_t *p = file_data + g_rebase_off;
    const uint8_t *end = p + g_rebase_size;

    int type = 0;
    uint64_t seg_offset = 0;
    int seg_index = 0;

    /* Helper macro to do one rebase at the current target */
    #define DO_ONE_REBASE() do { \
        if (seg_index < 0 || seg_index >= g_nsegments) return -1; \
        uint64_t target = g_segments[seg_index].vmaddr + seg_offset; \
        if (type == REBASE_TYPE_POINTER) { \
            uint64_t val = *(uint64_t *)(uintptr_t)target; \
            val += (uint64_t)g_slide; \
            *(uint64_t *)(uintptr_t)target = val; \
            if (g_verbose) { \
                if (g_verbose) fprintf(stderr, "macify: rebase at %#lx: %#lx -> %#lx (slide=%#lx)\n", \
                        (unsigned long)target, \
                        (unsigned long)(val - (uint64_t)g_slide), \
                        (unsigned long)val, (unsigned long)g_slide); \
            } \
        } \
        seg_offset += sizeof(uint64_t); \
    } while(0)

    while (p < end) {
        uint8_t op = *p++;
        uint8_t imm = op & 0x0F;
        op &= 0xF0;

        switch (op) {
            case REBASE_OPCODE_DONE:
                return 0;

            case REBASE_OPCODE_SET_TYPE_IMM:
                type = imm;
                break;

            case REBASE_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB:
                seg_index = imm;
                seg_offset = read_uleb128(&p, end);
                break;

            case REBASE_OPCODE_ADD_ADDR_ULEB:
                seg_offset += read_uleb128(&p, end);
                break;

            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                seg_offset += (uint64_t)imm * sizeof(uint64_t);
                break;

            case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                for (int i = 0; i < imm; i++) {
                    DO_ONE_REBASE();
                }
                break;

            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
                uint64_t count = read_uleb128(&p, end);
                for (uint64_t i = 0; i < count; i++) {
                    DO_ONE_REBASE();
                }
                break;
            }

            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
                DO_ONE_REBASE();
                seg_offset += read_uleb128(&p, end);
                break;
            }

            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(&p, end);
                uint64_t skip = read_uleb128(&p, end);
                for (uint64_t i = 0; i < count; i++) {
                    DO_ONE_REBASE();
                    seg_offset += skip;
                }
                break;
            }

            default:
                fprintf(stderr, "macify: unknown rebase opcode 0x%02x\n", op | imm);
                return -1;
        }
    }
    #undef DO_ONE_REBASE
    return 0;
}


/* Lazy bind support.
 *
 * Real macOS binaries use lazy binding: symbols in __la_symbol_ptr
 * are resolved on first call via dyld_stub_binder. We take the
 * simpler "eager bind" approach: resolve all lazy binds at load
 * time, filling __la_symbol_ptr entries with resolved addresses.
 * The app's stubs then jump directly to the resolved function.
 *
 * The lazy_bind opcodes use the same format as bind opcodes, but
 * are stored in a separate section. We reuse execute_binds() by
 * temporarily pointing it at the lazy_bind section.
 */

int execute_lazy_binds(uint8_t *file_data, size_t file_size) {
    if (g_lazy_bind_size == 0) return 0;

    /* Save original bind offsets, swap in lazy bind offsets, execute,
     * then restore. This reuses the bind opcode interpreter. */
    uint32_t save_bind_off  = g_bind_off;
    uint32_t save_bind_size = g_bind_size;

    g_bind_off  = g_lazy_bind_off;
    g_bind_size = g_lazy_bind_size;

    int result = execute_binds(file_data, file_size);

    g_bind_off  = save_bind_off;
    g_bind_size = save_bind_size;

    return result;
}


/* Chained fixups (modern macOS format).
 *
 * Modern macOS binaries (macOS 11+) use LC_DYLD_CHAINED_FIXUPS instead
 * of LC_DYLD_INFO bind/rebase opcodes. The fixups are stored as a chain
 * of entries within each segment's pages. Each entry is either:
 *   - A rebase: adds the slide to the value at that location
 *   - A bind: resolves an imported symbol and writes its address
 *
 * The chain is linked: each entry has a "next" offset to the next fixup
 * in the same page. The chain terminates when the "next" offset is 0.
 */

int execute_chained_fixups(uint8_t *file_data, size_t file_size) {
    if (g_verbose) fprintf(stderr, "macify: execute_chained_fixups called (off=%u size=%u)\n",
            g_chained_fixups_off, g_chained_fixups_size);
    if (!g_has_chained_fixups || g_chained_fixups_size == 0) return 0;
    if (g_chained_fixups_off + g_chained_fixups_size > file_size) {
        fprintf(stderr, "macify: chained fixups extend past EOF\n");
        return -1;
    }

    uint8_t *fixups = file_data + g_chained_fixups_off;
    dyld_chained_fixups_header *hdr = (dyld_chained_fixups_header *)fixups;

    if (hdr->fixups_version != 0) {
        fprintf(stderr, "macify: unsupported chained fixups version %u\n", hdr->fixups_version);
        return -1;
    }

    /* Parse the starts table */
    uint8_t *starts_base = fixups + hdr->starts_offset;
    /* The starts_in_image: first uint32 is starts_count, followed by offsets */
    uint32_t starts_count = *(uint32_t *)starts_base;
    uint32_t *starts = (uint32_t *)(starts_base + 4);

    /* Parse the imports table */
    uint8_t *imports_base = fixups + hdr->imports_offset;
    uint8_t *symbols_base = fixups + hdr->symbols_offset;

    if (g_verbose) {
        if (g_verbose) fprintf(stderr, "macify: chained fixups: %u segments, %u imports\n",
                starts_count, hdr->imports_count);
    }

    /* Process each segment's fixups */
    for (uint32_t seg_idx = 0; seg_idx < starts_count && seg_idx < (uint32_t)g_nsegments; seg_idx++) {
        if (starts[seg_idx] == 0) continue;  /* no fixups for this segment */

        /* The starts[seg_idx] offset is relative to starts_base */
        uint8_t *seg_starts = starts_base + starts[seg_idx];

        /* Parse dyld_chained_starts_in_segment
         * Layout: size(4) page_size(2) ptr_format(2) seg_offset(8) max_valid(4) page_count(2) page_start[](2 each)
         * Total header = 22 bytes, page_start[] starts at offset 22 */
        uint32_t seg_size = *(uint32_t *)seg_starts;
        uint16_t page_size = *(uint16_t *)(seg_starts + 4);
        uint16_t ptr_format = *(uint16_t *)(seg_starts + 6);
        uint64_t seg_offset = *(uint64_t *)(seg_starts + 8);
        uint32_t max_valid = *(uint32_t *)(seg_starts + 16);
        uint16_t page_count = *(uint16_t *)(seg_starts + 20);
        uint16_t *page_starts = (uint16_t *)(seg_starts + 22);  /* offset 22, not 24! */

        loaded_segment *seg = &g_segments[seg_idx];

        if (g_verbose) {
            if (g_verbose) fprintf(stderr, "macify: chained fixups for %s: ptr_format=%u pages=%u\n",
                    seg->name, ptr_format, page_count);
        }

        (void)seg_size; (void)max_valid; (void)seg_offset;

        /* Process each page */
        for (uint16_t page_idx = 0; page_idx < page_count; page_idx++) {
            uint16_t page_start = page_starts[page_idx];
            if (g_verbose) fprintf(stderr, "macify:   page %u: start=0x%x\n", page_idx, page_start);
            if (getenv("MACIFY_VERBOSE")) fflush(stderr);
            if (page_start == 0xFFFF) continue;  /* DYLD_CHAINED_PTR_START_NONE */
            /* page_start=0 means fixups start at beginning of page (valid) */

            uint8_t *page_base = (uint8_t *)(uintptr_t)seg->vmaddr + (uint64_t)page_idx * page_size;

            /* Walk the single fixup chain for this page.
             *
             * Apple's 64-bit chained fixup entry (8 bytes):
             *   bit  63      : bind flag (0=rebase, 1=bind)
             *   bits 51-62   : next (12 bits, in units of 4 bytes)
             *   bits 43-50   : high8 (rebase only -- extends target above 2^43)
             *
             * Rebase:  bits 0-42  = offset from image base (43 bits)
             *          runtime   = ((high8 << 43) | offset) + load_base
             * Bind:    bits 0-15 = ordinal (0-based import index)
             *          bits 16-31 = addend
             *
             * One chain per page, starting at page_start, linked by `next`
             * (byte offset = next * 4) until next == 0. Special ordinals
             * 0xFD/0xFE/0xFF (flat-lookup / main-exec / self) are not
             * supported and left as-is.
             */
            uint8_t *page_end = page_base + page_size;
            if (page_end > (uint8_t *)(uintptr_t)seg->vmaddr + seg->vmsize) {
                page_end = (uint8_t *)(uintptr_t)seg->vmaddr + seg->vmsize;
            }

            /* Compute load_base once (slid vmaddr of first non-PAGEZERO segment).
             * Stored in a static so subsequent calls reuse it. */
            static uint64_t load_base = 0;
            if (load_base == 0) {
                for (int si = 0; si < g_nsegments; si++) {
                    if (g_segments[si].is_pagezero) continue;
                    load_base = g_segments[si].vmaddr;  /* already slid */
                    break;
                }
            }

            uint8_t *chain_ptr = page_base + page_start;
            if (chain_ptr + 8 > page_end) continue;

            int chain_iter = 0;
            while (chain_iter < 16384) {
                uint64_t value = *(uint64_t *)chain_ptr;
                bool is_bind = (value >> 63) & 1;
                uint32_t next = (value >> 51) & 0xFFF;

                if (is_bind) {
                    uint32_t ordinal = value & 0xFFFF;
                    uint32_t addend = (value >> 16) & 0xFFFF;

                    if (ordinal >= hdr->imports_count) {
                        /* Out-of-range import index — leave as-is. */
                    } else {
                        uint32_t imp_raw = *(uint32_t *)(imports_base + ordinal * 4);
                        int lib_ordinal = imp_raw & 0xFF;
                        uint32_t name_offset = (imp_raw >> 9) & 0x7FFFFF;
                        const char *sym_name = (const char *)(symbols_base + name_offset);
                        const char *sym = sym_name;
                        if (sym[0] == '_') sym++;

                        /* Handle special ordinals:
                         *   0x00 (0)   = flat lookup (search all libraries)
                         *   0xFB (251) = self
                         *   0xFC (252) = main executable
                         *   0xFD (253) = flat lookup
                         *   0xFE (254) = main executable
                         *   0xFF (255) = flat lookup
                         * For all special ordinals, use flat namespace lookup. */
                        void *addr;
                        if (lib_ordinal == 0 || lib_ordinal >= 0xFB) {
                            /* Flat namespace lookup — search all loaded libraries */
                            addr = resolve_symbol(-1, sym);
                        } else {
                            addr = resolve_symbol(lib_ordinal - 1, sym);
                        }
                        if (addr) {
                            *(uint64_t *)chain_ptr = (uint64_t)(uintptr_t)addr + addend;
                            if (getenv("MACIFY_TRACE_FIXUPS")) {
                                if (g_verbose) fprintf(stderr, "macify: fixup sym=%s -> %p (GOT=%p)\n", sym, addr, (void*)chain_ptr);
                                fflush(stderr);
                            }
                            if (strcmp(sym, "malloc_size") == 0) {
                                if (getenv("MACIFY_VERBOSE")) fprintf(stderr, "macify: chained fixup malloc_size at chain_ptr=%p (page+0x%lx) -> %p\n",
                                        (void*)chain_ptr, (unsigned long)(chain_ptr - page_base), addr);
                                if (getenv("MACIFY_VERBOSE")) fflush(stderr);
                            }
                        } else {
                            /* Stub unresolved symbols instead of leaving GOT as NULL */
                            extern long macify_unresolved_stub(void);
                            addr = (void *)macify_unresolved_stub;
                            *(uint64_t *)chain_ptr = (uint64_t)(uintptr_t)addr + addend;
                            if (getenv("MACIFY_TRACE_FIXUPS")) {
                                fprintf(stderr, "macify: chained fixup STUBBED: sym=%s lib_ordinal=%d\n",
                                        sym, lib_ordinal);
                            }
                        }
                    }
                } else {
                    /* Rebase fixup: target is OFFSET from image base */
                    uint64_t target = value & 0x7FFFFFFFFFFULL;
                    uint8_t  high8 = (value >> 43) & 0xFF;
                    uint64_t static_offset = ((uint64_t)high8 << 43) | target;
                    *(uint64_t *)chain_ptr = static_offset + load_base;
                    if (getenv("MACIFY_TRACE_FIXUPS")) {
                        fprintf(stderr, "macify: rebase -> 0x%lx (GOT=%p)\n",
                                (unsigned long)(static_offset + load_base), (void*)chain_ptr);
                    }
                }

                if (next == 0) break;
                if (getenv("MACIFY_TRACE_FIXUPS")) {
                    fprintf(stderr, "macify: chain next=%d -> offset 0x%lx\n",
                            next, (unsigned long)(chain_ptr - page_base + (size_t)next * 4));
                    fflush(stderr);
                }
                chain_ptr += (size_t)next * 4;  /* stride = 4 bytes */
                if (chain_ptr + 8 > page_end) break;
                chain_iter++;
            }
        }
    }
    return 0;
}







