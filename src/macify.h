/*
 * macify.h — shared definitions for Mac-ify loader
 *
 * All structures, constants, globals, and function declarations
 * used across the modular loader.
 */

#ifndef MACIFY_H
#define MACIFY_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <dlfcn.h>
#include <link.h>

/* ============================================================
 * Mach-O constants
 * ============================================================ */

#define MH_MAGIC_64         0xFEEDFACFu
#define CPU_TYPE_X86_64     0x01000007u
#define CPU_SUBTYPE_X86_64_ALL 0x80000003u
#define MH_EXECUTE          0x02u
#define MH_PIE              0x200000u
#define LC_SEGMENT_64       0x19u
#define LC_UNIXTHREAD       0x05u
#define LC_LOAD_DYLIB       0x0Cu
#define LC_LOAD_WEAK_DYLIB  (0x18u | 0x80000000u)  /* LC_REQ_DYLD bit set */
#define LC_REEXPORT_DYLIB   (0x1Fu | 0x80000000u)
#define LC_LAZY_LOAD_DYLIB  0x20u
#define LC_DYLD_INFO_ONLY   0x80000022u
#define LC_MAIN             0x80000028u
#define LC_SYMTAB           0x02u
#define LC_DYSYMTAB         0x0Bu
#define LC_DYLD_CHAINED_FIXUPS 0x80000034u
#define LC_DYLD_EXPORTS_TRIE 0x80000033u
#define x86_THREAD_STATE64  0x04u

#define VM_PROT_READ        0x01
#define VM_PROT_WRITE       0x02
#define VM_PROT_EXECUTE     0x04

/* Section types */
#define S_REGULAR                       0x00
#define S_ZEROFILL                      0x01
#define S_CSTRING_LITERALS              0x02
#define S_NON_LAZY_SYMBOL_POINTERS      0x06
#define S_LAZY_SYMBOL_POINTERS          0x07
#define S_SYMBOL_STUBS                  0x08

#define S_ATTR_PURE_INSTRUCTIONS        0x80000000
#define S_ATTR_SOME_INSTRUCTIONS        0x00000400

#define INDIRECT_SYMBOL_LOCAL   0x80000000u
#define INDIRECT_SYMBOL_ABS     0x40000000u

/* Chained fixup pointer formats */
#define DYLD_CHAINED_PTR_64_OFFSET    2
#define DYLD_CHAINED_PTR_64_BIND      3
#define DYLD_CHAINED_PTR_64_OFFSET_64 6
#define DYLD_CHAINED_PTR_64_BIND_64   7

/* ============================================================
 * Mach-O structures
 * ============================================================ */

typedef struct {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
} mach_header_64;

typedef struct {
    uint32_t cmd, cmdsize;
    char     segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    int32_t  maxprot, initprot;
    uint32_t nsects, flags;
} segment_command_64;

typedef struct {
    uint64_t rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags, cs, fs, gs;
} __attribute__((packed)) x86_thread_state64_t;

typedef struct {
    uint32_t cmd, cmdsize;
    uint64_t entryoff, stacksize;
} entry_point_command;

typedef struct {
    uint32_t cmd, cmdsize;
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} dylib_command;

typedef struct {
    uint32_t cmd, cmdsize;
    uint32_t rebase_off, rebase_size;
    uint32_t bind_off, bind_size;
    uint32_t weak_bind_off, weak_bind_size;
    uint32_t lazy_bind_off, lazy_bind_size;
    uint32_t export_off, export_size;
} dyld_info_command;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} section_64;

typedef struct {
    uint32_t cmd, cmdsize;
    uint32_t symoff, nsyms, stroff, strsize;
} symtab_command;

typedef struct {
    uint32_t cmd, cmdsize;
    uint32_t ilocalsym, nlocalsym;
    uint32_t iextdefsym, nextdefsym;
    uint32_t iundefsym, nundefsym;
    uint32_t tocoff, ntoc;
    uint32_t modtaboff, nmodtab;
    uint32_t extrefsymoff, nextrefsyms;
    uint32_t indirectsymoff, nindirectsyms;
    uint32_t extreloff, nextrel;
    uint32_t locreloff, nlocrel;
} dysymtab_command;

typedef struct {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} nlist_64;

typedef struct {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t symbols_format;
} dyld_chained_fixups_header;

/* ============================================================
 * Loaded segment/section tracking
 * ============================================================ */

#define MAX_SEGMENTS 32
#define MAX_SECTIONS 64
#define MAX_DYLIBS 32

typedef struct {
    uint64_t vmaddr;
    uint64_t vmsize;
    int      prot;
    int      target_prot;
    char     name[16];
    int      is_pagezero;
} loaded_segment;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} loaded_section;

typedef struct {
    char  name[256];
    void *handle;
    void *libc_handle;
    void *libm_handle;
} loaded_dylib;

/* A loaded Mach-O shared library (dylib).
 * Unlike loaded_dylib (which tracks ELF .so handles), this tracks
 * Mach-O dylibs that we load into memory ourselves. */
#define MAX_MACHO_DYLIBS 64
#define MAX_DYLIB_SYMS   4096

typedef struct {
    char     name[256];      /* dylib name/path */
    uint8_t *file_data;      /* mmap'd file data (kept for fixup processing) */
    size_t   file_size;
    uint64_t slide;          /* ASLR slide applied to this dylib */
    int      n_exports;      /* number of exported symbols */
    struct {
        char    name[128];   /* symbol name (without leading _) */
        void   *addr;        /* resolved address */
    } exports[MAX_DYLIB_SYMS];
} macho_dylib;

/* ============================================================
 * Global state
 * ============================================================ */

extern loaded_segment g_segments[MAX_SEGMENTS];
extern int g_nsegments;
extern loaded_section g_sections[MAX_SECTIONS];
extern int g_nsections;
extern loaded_dylib g_dylibs[MAX_DYLIBS];
extern int g_ndylibs;
extern macho_dylib g_macho_dylibs[MAX_MACHO_DYLIBS];
extern int g_n_macho_dylibs;

/* Text range of the loaded macOS binary, for SIGSEGV recovery. */
extern uintptr_t g_macos_text_lo;
extern uintptr_t g_macos_text_hi;

extern uint64_t g_entry_rip;
extern int64_t  g_slide;
extern bool     g_verbose;
extern bool     g_no_fast_path;

/* tls_g address (for Go binaries). Go stores the current goroutine
 * pointer here. Set by setup_gs_base() in runtime.c. 0 for non-Go. */
extern uint64_t g_tls_g_addr;

extern uint64_t g_fast_path_sites;
extern uint64_t g_slow_path_sites;
extern uint64_t g_slow_path_calls;
extern bool     g_stats_printed;

extern uint32_t g_rebase_off, g_rebase_size;
extern uint32_t g_bind_off, g_bind_size;
extern uint32_t g_lazy_bind_off, g_lazy_bind_size;
extern uint32_t g_chained_fixups_off, g_chained_fixups_size;
extern bool     g_has_chained_fixups;

extern uint32_t g_symtab_off, g_symtab_nsyms;
extern uint32_t g_strtab_off, g_strtab_size;
extern uint32_t g_indirectsym_off, g_indirectsym_count;

/* ============================================================
 * Function declarations
 * ============================================================ */

/* segments.c */
int prot_from_macos(int macos_prot);
loaded_section *find_section(const char *segname, const char *sectname);
bool section_is_code(const loaded_section *s);
int map_segment(segment_command_64 *seg, uint8_t *file_data, size_t file_size);
uint8_t *load_file(const char *path, size_t *out_size);

/* syscall.c */
void sigill_handler(int sig, siginfo_t *info, void *uctx);
void sigill_handler_pre_resolve(void);
void crash_handler(int sig, siginfo_t *info, void *uctx);
void print_stats(void);
int patch_syscalls_in_segment(loaded_segment *seg);

/* fixups.c */
uint64_t read_uleb128(const uint8_t **p, const uint8_t *end);
int64_t read_sleb128(const uint8_t **p, const uint8_t *end);
int execute_binds(uint8_t *file_data, size_t file_size);
int execute_rebases(uint8_t *file_data, size_t file_size);
int execute_lazy_binds(uint8_t *file_data, size_t file_size);
int execute_chained_fixups(uint8_t *file_data, size_t file_size);
void *resolve_symbol(int ordinal_idx, const char *sym);
void register_extra_handle(void *handle);

/* macho_dylib.c — Mach-O shared library loader */
int macho_load_dylib(const char *path);
void *macho_dylib_lookup(const char *sym);

/* runtime.c */
uint64_t setup_stack(int argc, char **argv, char **envp, void **stack_base, size_t *stack_size);
void jump_to_entry(uint64_t entry, uint64_t stack_top) __attribute__((noreturn));
void call_main_and_exit(uint64_t entry, uint64_t stack_top) __attribute__((noreturn));

/* prefix.c — macOS filesystem prefix (like Wine's drive_c) */
void macify_init_prefix(void);
int macify_translate_path(const char *path, char *out, size_t out_size);
int macify_should_hide_path(const char *path);
const char *macify_get_prefix(void);

#endif /* MACIFY_H */
const char *bsd_syscall_name(uint32_t bsd_nr);
