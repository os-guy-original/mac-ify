#!/usr/bin/env python3
"""Analyze a core dump from macify+ripgrep crash.
Extracts register state and stack trace from the core file."""
import struct
import sys
import os

CORE = "/home/z/my-project/mac-ify/core"

with open(CORE, "rb") as f:
    data = f.read()

print(f"Core file size: {len(data)} bytes")

# ELF header
if data[:4] != b'\x7fELF':
    print("Not an ELF file!")
    sys.exit(1)

ei_class = data[4]  # 1=32-bit, 2=64-bit
print(f"ELF class: {ei_class} ({'64-bit' if ei_class == 2 else '32-bit'})")

if ei_class != 2:
    print("Only 64-bit supported")
    sys.exit(1)

# ELF64 header
e_type = struct.unpack('<H', data[16:18])[0]
e_phoff = struct.unpack('<Q', data[32:40])[0]
e_phentsize = struct.unpack('<H', data[54:56])[0]
e_phnum = struct.unpack('<H', data[56:58])[0]
e_shoff = struct.unpack('<Q', data[40:48])[0]
e_shentsize = struct.unpack('<H', data[58:60])[0]
e_shnum = struct.unpack('<H', data[60:62])[0]
e_shstrndx = struct.unpack('<H', data[62:64])[0]

print(f"ELF type: {e_type} (4=core)")
print(f"Program headers: {e_phnum} at offset {e_phoff}")

# Parse program headers (NOTE segments)
prstatus = None
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack('<I', data[off:off+4])[0]
    p_offset = struct.unpack('<Q', data[off+8:off+16])[0]
    p_filesz = struct.unpack('<Q', data[off+32:off+40])[0]
    p_name = ""
    if p_type == 4:  # PT_NOTE
        # Parse NT_PRSTATUS
        note_off = p_offset
        while note_off < p_offset + p_filesz:
            n_namesz, n_descsz, n_type = struct.unpack('<III', data[note_off:note_off+12])
            name = data[note_off+12:note_off+12+n_namesz].rstrip(b'\x00').decode()
            desc = data[note_off+12+n_namesz:note_off+12+n_namesz+n_descsz]
            # Pad to 8-byte boundary
            note_off += 12 + ((n_namesz + 3) & ~3) + ((n_descsz + 3) & ~3)
            if n_type == 1:  # NT_PRSTATUS
                prstatus = desc
                print(f"\nFound NT_PRSTATUS (desc size={n_descsz})")
                break
        if prstatus:
            break

if prstatus is None:
    print("No NT_PRSTATUS found!")
    sys.exit(1)

# NT_PRSTATUS layout for x86_64 Linux:
#   siginfo (128 bytes) — but actually prstatus starts with:
#   struct elf_prstatus {
#       elf_siginfo pr_info;     // 16 bytes (si_signo, si_code, si_errno + padding)
#       short pr_cursig;          // 2 bytes
#       char padding[6];          // align to 8
#       sigset_t pr_sigpend;      // 128 bytes
#       sigset_t pr_sighold;      // 128 bytes
#       pid_t pr_pid;             // 4
#       pid_t pr_ppid;            // 4
#       pid_t pr_pgrp;            // 4
#       pid_t pr_sid;             // 4
#       struct timeval pr_utime;  // 16
#       struct timeval pr_stime;  // 16
#       struct timeval pr_cutime; // 16
#       struct timeval pr_cstime; // 16
#       elf_gregset_t pr_reg;     // 27 * 8 = 216 bytes (the registers!)
#       ...
#   }
# Total before pr_reg = 16 + 2 + 6 + 128 + 128 + 4 + 4 + 4 + 4 + 16 + 16 + 16 + 16 = 356 bytes
# But let me check the actual offset by looking for the pattern.

# Actually, the standard layout has pr_reg at offset 112 in some implementations.
# Let me try different offsets.

# The elf_gregset_t for x86_64 has 23 registers in this order:
# 0: r15, 1: r14, 2: r13, 3: r12, 4: rbp, 5: rbx, 6: r11, 7: r10,
# 8: r9, 9: r8, 10: rax, 11: rcx, 12: rdx, 13: rsi, 14: rdi,
# 15: orig_rax, 16: rip, 17: cs, 18: eflags, 19: rsp, 20: ss,
# 21: fs_base, 22: gs_base

# Try to find the registers by looking for a valid RIP (in 0x7f... range)
# The crash rip should be near-NULL (0x3ce from earlier crash)
# or in ripgrep's __TEXT.

print(f"\nSearching for register context in prstatus ({len(prstatus)} bytes)...")

# The elf_gregset_t for x86_64 has 23 registers (23*8 = 184 bytes).
# desc size = 336, so pr_reg starts at offset 336 - 184 = 152.
# But let me search for a plausible RIP instead of hardcoding.

names = ['r15','r14','r13','r12','rbp','rbx','r11','r10',
         'r9','r8','rax','rcx','rdx','rsi','rdi',
         'orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base']

best_offset = None
for trial_offset in range(0, len(prstatus) - 23*8 + 1, 1):
    try:
        regs = struct.unpack('<23Q', prstatus[trial_offset:trial_offset+23*8])
    except struct.error:
        break
    rip = regs[16]
    rsp = regs[19]
    cs = regs[17]
    ss = regs[20]
    # Check: rip in 0x7f... range OR near-NULL (crash case)
    # AND rsp in 0x7f... range
    # AND cs == 0x33 AND ss == 0x2b (Linux x86_64 user mode)
    rip_ok = (0x7f0000000000 <= rip <= 0x7fffffffffff) or rip < 0x10000
    rsp_ok = (0x7f0000000000 <= rsp <= 0x7fffffffffff)
    cs_ok = (cs == 0x33)
    ss_ok = (ss == 0x2b)
    if rip_ok and rsp_ok and cs_ok and ss_ok:
        print(f"\n  Found registers at offset {trial_offset}:")
        for n, v in zip(names, regs):
            print(f"    {n:10s} = {v:#018x}")
        best_offset = trial_offset
        break

if best_offset is None:
    print("  Could not find plausible register context")
    # Dump raw as hex for manual inspection
    print("  Raw prstatus hex (first 336 bytes):")
    for i in range(0, len(prstatus), 16):
        hex_part = ' '.join(f'{b:02x}' for b in prstatus[i:i+16])
        print(f"    {i:4d}: {hex_part}")

