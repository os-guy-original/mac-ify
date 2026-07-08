#!/usr/bin/env python3
"""Combined core analysis: extract registers + memory map + backtrace."""
import struct

CORE = "/home/z/my-project/mac-ify/core"
RG = "/home/z/my-project/mac-ify/tests/real/rg_macos"

with open(CORE, "rb") as f:
    core = f.read()

# Parse ELF header
e_phoff = struct.unpack('<Q', core[32:40])[0]
e_phentsize = struct.unpack('<H', core[54:56])[0]
e_phnum = struct.unpack('<H', core[56:58])[0]

load_segments = []
prstatus = None
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack('<I', core[off:off+4])[0]
    p_offset = struct.unpack('<Q', core[off+8:off+16])[0]
    p_vaddr = struct.unpack('<Q', core[off+16:off+24])[0]
    p_filesz = struct.unpack('<Q', core[off+32:off+40])[0]
    if p_type == 1:
        load_segments.append((p_vaddr, p_filesz, p_offset))
    elif p_type == 4:
        note_off = p_offset
        while note_off < p_offset + p_filesz and not prstatus:
            n_namesz, n_descsz, n_type = struct.unpack('<III', core[note_off:note_off+12])
            desc = core[note_off+12+((n_namesz+3)&~3):note_off+12+((n_namesz+3)&~3)+n_descsz]
            if n_type == 1:
                prstatus = desc
            note_off += 12 + ((n_namesz+3)&~3) + ((n_descsz+3)&~3)

# Find registers in prstatus
names = ['r15','r14','r13','r12','rbp','rbx','r11','r10',
         'r9','r8','rax','rcx','rdx','rsi','rdi',
         'orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base']
regs = {}
for trial in range(0, len(prstatus) - 23*8 + 1, 1):
    vals = struct.unpack('<23Q', prstatus[trial:trial+23*8])
    if vals[17] == 0x33 and vals[20] == 0x2b and  \
       (0x7f0000000000 <= vals[19] <= 0x7fffffffffff):
        regs = dict(zip(names, vals))
        break

rip = regs['rip']
rsp = regs['rsp']
print(f"Crash rip = {rip:#018x}")
print(f"Crash rsp = {rsp:#018x}")
print(f"  rax={regs['rax']:#x} rbx={regs['rbx']:#x} rcx={regs['rcx']:#x}")
print(f"  rdi={regs['rdi']:#x} rsi={regs['rsi']:#x} rdx={regs['rdx']:#x}")
print(f"  rbp={regs['rbp']:#x} r8={regs['r8']:#x} r9={regs['r9']:#x}")

# Find ripgrep slide
with open(RG, "rb") as f:
    rg = f.read()
rg_ncmds = struct.unpack('<I', rg[16:20])[0]
rg_off = 32
rg_segs = []
for i in range(rg_ncmds):
    cmd, cmdsize = struct.unpack('<II', rg[rg_off:rg_off+8])
    if cmd == 0x19:
        segname = rg[rg_off+8:rg_off+24].rstrip(b'\x00').decode()
        vmaddr, vmsize = struct.unpack('<QQ', rg[rg_off+24:rg_off+40])
        rg_segs.append((segname, vmaddr, vmsize))
    rg_off += cmdsize

rg_text_size = next(s[2] for s in rg_segs if s[0] == '__TEXT')
rg_slide = None
for vaddr, filesz, off in load_segments:
    if filesz == rg_text_size:
        rg_slide = vaddr - 0x100000000
        break
print(f"\nripgrep slide = {rg_slide:#x}")
print(f"ripgrep __TEXT = {0x100000000+rg_slide:#x} - {0x100000000+rg_slide+rg_text_size:#x}")

# Where is rip?
print(f"\nrip analysis:")
for vaddr, filesz, off in load_segments:
    if vaddr <= rip < vaddr + filesz:
        print(f"  rip in PT_LOAD {vaddr:#x}-{vaddr+filesz:#x} (offset {rip-vaddr:#x})")
        for segname, svmaddr, svmsize in rg_segs:
            slid = svmaddr + rg_slide
            if slid <= rip < slid + svmsize:
                print(f"  -> ripgrep {segname}+{rip-slid:#x}")
                break
        else:
            print(f"  -> NOT in ripgrep (library)")
        break

# Stack trace
print(f"\nStack trace (scanning 8KB from rsp):")
for vaddr, filesz, off in load_segments:
    if vaddr <= rsp < vaddr + filesz:
        stack_off = off + (rsp - vaddr)
        stack_data = core[stack_off:stack_off + 8192]
        for i in range(0, len(stack_data), 8):
            val = struct.unpack('<Q', stack_data[i:i+8])[0]
            if val < 0x1000:
                continue
            loc = None
            for segname, svmaddr, svmsize in rg_segs:
                slid = svmaddr + rg_slide
                if slid <= val < slid + svmsize:
                    loc = f"ripgrep {segname}+{val-slid:#x}"
                    break
            if not loc and 0x7f0000000000 <= val <= 0x7fffffffffff:
                for v2, f2, _ in load_segments:
                    if v2 <= val < v2 + f2:
                        loc = f"library {v2:#x}+{val-v2:#x}"
                        break
            if loc:
                print(f"  rsp+{i:#x}: {val:#018x} -> {loc}")
        break
