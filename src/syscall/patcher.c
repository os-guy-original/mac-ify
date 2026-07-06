/* patcher.c — patch syscall instructions and Go systemstack in text segments */
#include "syscall_internal.h"

/* Helper: scan a byte range for syscall instructions and patch them.
 * base = segment base address (slid)
 * seg_start = offset within base where the range starts
 * seg_len = length of the range
 * Returns number of sites patched (fast + slow), or -1 on error. */
int patch_syscalls_in_range(loaded_segment *seg, uint8_t *base,
                                    size_t range_start, size_t range_len,
                                    int *fast_count, int *slow_count) {
    size_t range_end = range_start + range_len;
    if (range_end > seg->vmsize) range_end = seg->vmsize;

    for (size_t i = range_start; i + 1 < range_end; i++) {
        if (base[i] != 0x0F || base[i+1] != 0x05) continue;  /* not syscall */

        /* CRITICAL: Check that this 0F 05 is NOT inside another instruction.
         * The byte pattern 0F 05 can appear as:
         *   - Part of a JMP/CALL rel32 displacement (e.g., e9 0f 05 00 00)
         *   - Part of a LEA rip+disp32 displacement (e.g., 48 8d 35 0f 05 00 00)
         *   - Part of a MOV imm32 (e.g., b8 0f 05 00 00)
         *   - Part of a CMP imm32 (e.g., 81 f9 0f 05 00 00)
         *   - Part of conditional jump (e.g., 0f 84 0f 05 00 00)
         *
         * Strategy: only patch 0F 05 if we can find a macOS syscall pattern
         * within 32 bytes BEFORE it. Two patterns:
         *   1. mov eax, 0x2000XXXX (B8 XX XX 00 20) — static syscall number
         *   2. add rax, 0x2000000 (48 05 00 00 00 02) — Go's dynamic pattern:
         *      Go loads syscall number from stack/memory, adds 0x2000000 */
        {
            bool found_pattern = false;
            size_t scan_start = (i >= BACKWARD_SCAN_BYTES) ? (i - BACKWARD_SCAN_BYTES) : 0;
            for (size_t j = (i >= 5) ? (i - 5) : 0; j >= scan_start && j < i; j--) {
                /* Pattern 1: mov eax, 0x2000XXXX */
                if (base[j] == 0xB8 && j+4 < i &&
                    base[j+3] == 0x00 && base[j+4] == 0x20) {
                    if (j > 0 && base[j-1] >= 0x40 && base[j-1] <= 0x4F) continue;
                    found_pattern = true;
                    break;
                }
                /* Pattern 2: add rax, 0x2000000 (Go's dynamic syscall pattern)
                 * 48 05 00 00 00 02 = REX.W ADD RAX, imm32(0x02000000) */
                if (j >= 5 && base[j] == 0x48 && base[j+1] == 0x05 &&
                    base[j+2] == 0x00 && base[j+3] == 0x00 &&
                    base[j+4] == 0x00 && base[j+5] == 0x02) {
                    found_pattern = true;
                    break;
                }
                if (j == 0) break;
            }
            if (!found_pattern) continue;  /* Not a macOS syscall */
        }

        /* Found a syscall at offset i. Look backward for mov eax, 0x2000XXXX. */
        size_t mov_off = (size_t)-1;
        size_t mov_scan_start = (i >= BACKWARD_SCAN_BYTES) ? (i - BACKWARD_SCAN_BYTES) : 0;
        size_t scan_end   = (i >= 5) ? (i - 5) : 0;

        for (size_t j = scan_end + 1; j-- > mov_scan_start; ) {
            if (base[j] != 0xB8) continue;
            if (base[j+3] != 0x00 || base[j+4] != 0x20) continue;
            /* Skip if preceded by ANY REX prefix (0x40-0x4F). */
            if (j > 0 && base[j-1] >= 0x40 && base[j-1] <= 0x4F) continue;
            mov_off = j;
            break;
        }

        if (mov_off != (size_t)-1) {
            uint16_t bsd_nr = base[mov_off+1] | (base[mov_off+2] << 8);
            if (bsd_nr >= BSD_SYSCALL_MAX) {
                base[i+1] = 0x0B;  /* UD2 */
                (*slow_count)++;
                continue;
            }
            int16_t linux_nr = bsd_to_linux[bsd_nr];
            uint8_t flags = bsd_arg_flags[bsd_nr];
            bool needs_translation = (flags & ~ARG_FORCE_SLOW) != 0;
            bool force_slow = (flags & ARG_FORCE_SLOW) != 0;

            if (!g_no_fast_path && linux_nr > 0 && !needs_translation && !force_slow) {
                /* FAST PATH: rewrite the immediate. */
                base[mov_off+1] = (uint8_t)(linux_nr & 0xFF);
                base[mov_off+2] = (uint8_t)((linux_nr >> 8) & 0xFF);
                base[mov_off+3] = 0;
                base[mov_off+4] = 0;
                (*fast_count)++;
            } else {
                /* SLOW PATH: patch syscall to UD2. */
                base[i+1] = 0x0B;
                (*slow_count)++;
            }
        } else {
            /* No mov found: dynamically computed syscall #. SLOW PATH. */
            base[i+1] = 0x0B;
            if (g_verbose) {
                fprintf(stderr, "macify: patched dynamic syscall at offset 0x%lx (addr=%p, bytes now: %02x %02x)\n",
                        (unsigned long)i, (void *)(base + i), base[i], base[i+1]);
            }
            (*slow_count)++;
        }
    }
    return 0;
}

/* Forward declaration */
void patch_go_systemstack(loaded_segment *seg, uint8_t *base);

int patch_syscalls_in_segment(loaded_segment *seg) {
    if (!(seg->prot & PROT_EXEC)) return 0;
    if (seg->is_pagezero) return 0;

    if (mprotect((void *)(uintptr_t)seg->vmaddr, seg->vmsize,
                 PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        perror("mprotect RWX");
        return -1;
    }

    uint8_t *base = (uint8_t *)(uintptr_t)seg->vmaddr;
    int fast_count = 0, slow_count = 0;

    /* If we have section info, only patch code sections (more precise —
     * avoids false positives in data sections like __cstring, __const).
     * If no sections, patch the whole segment (backward compat). */
    bool has_code_sections = false;
    for (int i = 0; i < g_nsections; i++) {
        if (strncmp(g_sections[i].segname, seg->name, 16) == 0 &&
            section_is_code(&g_sections[i])) {
            has_code_sections = true;
            size_t sec_start = (size_t)(g_sections[i].addr - seg->vmaddr);
            size_t sec_len = (size_t)g_sections[i].size;
            patch_syscalls_in_range(seg, base, sec_start, sec_len,
                                    &fast_count, &slow_count);
            if (g_verbose) {
                fprintf(stderr, "macify: patched section %s.%s "
                                "(range %#lx+%lu, fast=%d slow=%d so far)\n",
                        g_sections[i].segname, g_sections[i].sectname,
                        (unsigned long)sec_start, (unsigned long)sec_len,
                        fast_count, slow_count);
            }
        }
    }

    if (!has_code_sections) {
        /* No code sections — scan the whole segment (legacy behavior) */
        patch_syscalls_in_range(seg, base, 0, seg->vmsize,
                                &fast_count, &slow_count);
    }

    /* Patch Go's systemstack to handle NULL m.curg.
     * This is safe for non-Go binaries — the pattern won't match. */
    patch_go_systemstack(seg, base);

    /* Downgrade to target protection. */
    if (mprotect((void *)(uintptr_t)seg->vmaddr, seg->vmsize,
                 seg->target_prot) < 0) {
        perror("mprotect final");
        return -1;
    }
    seg->prot = seg->target_prot;

    g_fast_path_sites += fast_count;
    g_slow_path_sites += slow_count;

    if (g_verbose) {
        fprintf(stderr, "macify: patched %d syscall site(s) in %s "
                        "(fast=%d, slow=%d%s)\n",
                fast_count + slow_count, seg->name, fast_count, slow_count,
                has_code_sections ? ", sections-only" : "");
    }
    return fast_count + slow_count;
}

/* Patch Go's systemstack function to handle NULL m.curg.
 * After running a function on g0's stack, systemstack tries to switch
 * back to m.curg's stack:
 *   mov gs:0x30, rax       ; set tls_g = m.curg (OK even if NULL)
 *   mov rsp, [rax+0x38]    ; CRASH if rax=m.curg=0!
 *   mov rbp, [rax+0x60]    ; also crashes
 *
 * We keep "mov gs:0x30, rax" intact (so tls_g gets set correctly),
 * and patch the following 8 bytes (mov rsp + mov rbp) to:
 *   test rax, rax          ; if m.curg is NULL...
 *   je +0x13 (to pop rbp; ret) ; ...skip stack switch and return
 *   nop * 3                ; padding
 * When m.curg is non-NULL, the nops run and the original mov rsp/rbp
 * are skipped — BUT that breaks the stack switch!
 *
 * Actually, we need a different approach. We patch ONLY the 4-byte
 * "mov rsp, [rax+0x38]" to a conditional that checks rax:
 * But 4 bytes isn't enough for test+je.
 *
 * Final approach: patch the 13-byte sequence starting at mov gs:0x30:
 *   Original (13 bytes): 65 48 89 04 25 30 00 00 00 48 8b 60 38
 *   Patched: 48 85 c0 74 07 65 48 89 04 25 30 00 00
 *   = test rax, rax; je +7; mov gs:0x30, rax
 *   If rax=0: skip mov gs:0x30 and the stack switch (je to mov rbp)
 *   If rax!=0: set tls_g, then fall through to mov rsp (unchanged at +13)
 * But mov rsp is at offset 13 and we only patched 13 bytes...
 * The mov rsp [rax+0x38] still runs if rax!=0. But if rax=0, we je past it.
 *
 * je +7: from offset 5 (end of je) to offset 12 = 7 bytes.
 * Offset 12 is the last byte of the original mov gs (0x38 of mov rsp).
 * That's wrong.
 *
 * Let me just use a simple approach:
 * Patch 13 bytes: test rax,rax; je +8; mov gs:0x30,rax; (mov rsp stays)
 * If rax=0: je to offset 13 = start of mov rsp, but rax is 0 so it crashes.
 * That doesn't help.
 *
 * OK, simplest correct approach: patch 14 bytes (mov gs + mov rsp):
 *   65 48 89 04 25 30 00 00 00 48 8b 60 38 XX
 * To:
 *   48 85 c0 74 08 65 48 89 04 25 30 00 00 90
 *   = test rax, rax; je +8; mov gs:0x30, rax; nop
 * If rax=0: je to offset 13 = nop, then falls through to mov rbp (which
 * also crashes). Still bad.
 *
 * ACTUAL simplest: just patch the 4-byte 'mov rsp, [rax+0x38]' to a
 * 4-byte 'ret' if rax is 0. Use CDQ+js trick? No.
 *
 * Just use: 48 85 c0 90 (test rax, rax; nop) replacing mov rsp.
 * Then the NEXT instruction (mov rbp, [rax+0x60]) will crash if rax=0.
 * But at least we can catch it.
 *
 * Actually the BEST approach: don't patch systemstack at all.
 * Instead, set m.curg = m.g0 BEFORE calling the Go entry point,
 * but do it AFTER rt0_go has set up g0 and m0. We can do this
 * in setup_gs_base after finding tls_g (which is near m0 in BSS). */
void patch_go_systemstack(loaded_segment *seg, uint8_t *base) {
    /* Patch systemstack's "switch back to m.curg" code.
     *
     * When m.curg is NULL (before any goroutine is scheduled), systemstack
     * crashes at mov rsp, [rax+0x38] where rax=m.curg=0.
     *
     * We patch 14 bytes (mov gs + mov rsp + REX) with:
     *   test rax, rax (3) — check m.curg
     *   je to trampoline (2) — if NULL: jump to trampoline (not pop rbp!)
     *   jmp trampoline2 (5) — if non-NULL: jump to trampoline2
     *   nop*4 (4)
     *
     * Trampoline (NULL m.curg path, in int3 padding):
     *   mov rax, [rbx] (3) — rax = m.g0 (rbx = g.m, m.g0 is at m+0)
     *   mov gs:0x30, rax (9) — set tls_g = m.g0 (keep valid g!)
     *   jmp to pop rbp;ret (5)
     * Total: 17 bytes
     *
     * Trampoline2 (non-NULL m.curg path, in int3 padding after trampoline):
     *   mov gs:0x30, rax (9) — set tls_g = m.curg
     *   mov rsp, [rax+0x38] (4) — switch stacks
     *   mov rbp, [rax+0x68] (4) — restore rbp
     *   jmp back to clearing (5)
     * Total: 22 bytes
     *
     * When m.curg=0: tls_g is set to m.g0 (NOT zeroed!), then return.
     * When m.curg!=0: original behavior (set tls_g, switch stacks, clear).
     */
    uint8_t pattern[] = {
        0x65, 0x48, 0x89, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0x48, 0x8b, 0x60, 0x38,
        0x48
    };

    for (size_t i = 0; i + sizeof(pattern) + 20 < seg->vmsize; i++) {
        if (memcmp(base + i, pattern, sizeof(pattern)) != 0) continue;
        if (base[i+14] != 0x8b || base[i+15] != 0x68) continue;

        /* Find int3 padding for TWO trampolines (need 17+22=39 bytes) */
        size_t trampoline_off = 0;
        for (size_t j = i + 20; j + 39 < seg->vmsize; j++) {
            if (base[j] == 0xCC && base[j+1] == 0xCC && base[j+2] == 0xCC) {
                size_t pad = 0;
                while (j + pad < seg->vmsize && base[j + pad] == 0xCC) pad++;
                if (pad >= 39) { trampoline_off = j; break; }
            }
        }
        if (trampoline_off == 0) continue;

        /* Find pop rbp; ret (5d c3) */
        size_t pop_ret_off = 0;
        for (size_t j = i + 17; j < i + 50; j++) {
            if (base[j] == 0x5d && base[j+1] == 0xc3) { pop_ret_off = j; break; }
        }
        if (pop_ret_off == 0) continue;

        /* Trampoline1 (NULL m.curg path) at trampoline_off:
         *   mov rax, [rbx] (3 bytes: 48 8b 03) — rax = m.g0 (rbx = g.m, m+0 = m.g0)
         *   mov gs:0x30, rax (9 bytes: 65 48 89 04 25 30 00 00 00)
         *   jmp to pop rbp;ret (5 bytes: E9 XX XX XX XX)
         * Total: 17 bytes */
        size_t t1_off = trampoline_off;
        int32_t t1_jmp_to_pop = (int32_t)(pop_ret_off - (t1_off + 17 + 5));

        uint8_t t1[22]; /* 17 bytes + padding */
        t1[0] = 0x48; t1[1] = 0x8b; t1[2] = 0x03;  /* mov rax, [rbx] (m.g0) */
        memcpy(&t1[3], pattern, 9);                  /* mov gs:0x30, rax */
        t1[12] = 0xE9;                               /* jmp to pop rbp;ret */
        memcpy(&t1[13], &t1_jmp_to_pop, 4);
        memset(&t1[17], 0x90, 5);                    /* nop padding */
        memcpy(base + t1_off, t1, 22);

        /* Trampoline2 (non-NULL m.curg path) at trampoline_off + 22:
         *   mov gs:0x30, rax (9 bytes)
         *   mov rsp, [rax+0x38] (4 bytes)
         *   mov rbp, [rax+0x68] (4 bytes)
         *   jmp back to clearing at i+17 (5 bytes)
         * Total: 22 bytes */
        size_t t2_off = trampoline_off + 22;
        int32_t t2_jmp_back = (int32_t)((i + 17) - (t2_off + 22));

        uint8_t t2[22];
        memcpy(&t2[0], pattern, 9);      /* mov gs:0x30, rax */
        memcpy(&t2[9], &pattern[9], 4);  /* mov rsp, [rax+0x38] */
        t2[13] = 0x48; t2[14] = 0x8b; t2[15] = 0x68; t2[16] = base[i+16];
        t2[17] = 0xE9;
        memcpy(&t2[18], &t2_jmp_back, 4);
        memcpy(base + t2_off, t2, 22);

        /* Patch 14 bytes: test + je(near) + jmp + nop
         * Use near je (0F 84) because trampoline may be far away.
         * test rax, rax (3) + je near (6) + jmp (5) = 14 bytes. Perfect! */
        int32_t je_offset = (int32_t)(t1_off - (i + 3 + 6));  /* from end of je */
        int32_t jmp_offset = (int32_t)(t2_off - (i + 14));    /* from end of jmp */

        uint8_t patch[14];
        patch[0] = 0x48; patch[1] = 0x85; patch[2] = 0xC0;  /* test rax, rax */
        patch[3] = 0x0F; patch[4] = 0x84;                    /* je near (4-byte offset) */
        memcpy(&patch[5], &je_offset, 4);
        patch[9] = 0xE9;                                      /* jmp to trampoline2 */
        memcpy(&patch[10], &jmp_offset, 4);
        memcpy(base + i, patch, sizeof(patch));

        if (g_verbose) {
            fprintf(stderr, "macify: patched systemstack at 0x%lx -> t1=0x%lx t2=0x%lx\n",
                    (unsigned long)(seg->vmaddr + i),
                    (unsigned long)(seg->vmaddr + t1_off),
                    (unsigned long)(seg->vmaddr + t2_off));
        }
        return;
    }
}

/* Print all loaded libraries (for crash debugging). */
static int dl_iterate_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    const char *name = info->dlpi_name;
    if (!name || !*name) name = "(main executable)";
    fprintf(stderr, "    base=0x%lx name=%s\n",
            (unsigned long)info->dlpi_addr, name);
    return 0;
}

int print_loaded_libs(void) {
    fprintf(stderr, "  Loaded libraries:\n");
    dl_iterate_phdr(dl_iterate_cb, NULL);
    return 0;
}
