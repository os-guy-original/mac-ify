#!/usr/bin/env python3
"""Analyze core dump: find memory map, identify crash location, extract backtrace."""
import struct
import sys

CORE = "/home/z/my-project/mac-ify/core"
RG = "/home/z/my-project/mac-ify/tests/real/rg_macos"

with open(CORE, "rb") as f:
    core = f.read()

# Parse ELF header
e_phoff = struct.unpack('<Q', core[32:40])[0]
e_phentsize = struct.unpack('<H', core[54:56])[0]
e_phnum = struct.unpack('<H', core[56:58])[0]

# Parse program headers — find PT_LOAD (1) and PT_NOTE (4)
load_segments = []  # (vaddr, filesz, offset in core file)
notes = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack('<I', core[off:off+4])[0]
    p_vaddr = struct.unpack('<Q', core[off+16:off+24])[0]
    p_offset = struct.unpack('<Q', core[off+8:off+16])[0]
    p_filesz = struct.unpack('<Q', core[off+32:off+40])[0]
    if p_type == 1:  # PT_LOAD
        load_segments.append((p_vaddr, p_filesz, p_offset))
    elif p_type == 4:  # PT_NOTE
        notes.append((p_offset, p_filesz))

print(f"Memory map ({len(load_segments)} PT_LOAD segments):")
for vaddr, filesz, off in sorted(load_segments):
    print(f"  {vaddr:#014x} - {vaddr+filesz:#014x} ({filesz:#x} bytes, core offset {off:#x})")

# Read ripgrep binary to get its segment layout
with open(RG, "rb") as f:
    rg = f.read()
rg_magic, _, _, _, ncmds, _, _, _ = struct.unpack('<IiiIIIII', rg[:32])
rg_off = 32
rg_segs = []
for i in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', rg[rg_off:rg_off+8])
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = rg[rg_off+8:rg_off+24].rstrip(b'\x00').decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', rg[rg_off+24:rg_off+56])
        rg_segs.append((segname, vmaddr, vmsize))
    rg_off += cmdsize

# Find ripgrep's slide by matching its __TEXT segment (size 0x408000)
# against a PT_LOAD segment of the same size
rg_text_size = next(s[2] for s in rg_segs if s[0] == '__TEXT')
rg_slide = None
for vaddr, filesz, off in load_segments:
    if filesz == rg_text_size:
        rg_slide = vaddr - rg_segs[0][1]  # vaddr - static_vmaddr of __TEXT
        # Actually __TEXT static vmaddr = 0x100000000
        rg_slide = vaddr - 0x100000000
        print(f"\nripgrep __TEXT found at core vaddr {vaddr:#x}")
        print(f"  static __TEXT vmaddr = 0x100000000")
        print(f"  slide = {rg_slide:#x}")
        break

if rg_slide is None:
    print("\nCould not find ripgrep's __TEXT segment!")
    # Try to identify by looking for the entry point
    rg_slide = 0

# Now check where the crash rip is
rip = 0x00007f9f49cba1f9
rsp = 0x00007f9f48847000
print(f"\nCrash rip = {rip:#x}")
print(f"Crash rsp = {rsp:#x}")

# Check if rip is in any loaded segment
for vaddr, filesz, off in load_segments:
    if vaddr <= rip < vaddr + filesz:
        print(f"  rip is in PT_LOAD at {vaddr:#x} (offset {rip-vaddr:#x} into segment)")
        # Check if it's in ripgrep
        for segname, svmaddr, svmsize in rg_segs:
            slid_addr = svmaddr + rg_slide
            if slid_addr <= rip < slid_addr + svmsize:
                print(f"  -> ripgrep segment {segname} (static offset {rip - slid_addr:#x})")
                break
        else:
            print(f"  -> NOT in ripgrep (some library)")
        break

# Check if rip is in libc or another library by looking at the core file's
# mapped files. We can't easily get file names from the core, but we can
# check if rip matches known library addresses.

# Now read the stack to find return addresses
print(f"\nStack trace (return addresses on stack at rsp={rsp:#x}):")
# Find the PT_LOAD segment containing rsp
for vaddr, filesz, off in load_segments:
    if vaddr <= rsp < vaddr + filesz:
        stack_core_off = off + (rsp - vaddr)
        stack_data = core[stack_core_off:stack_core_off + 4096]
        print(f"  Stack found in PT_LOAD at {vaddr:#x} (core offset {stack_core_off:#x})")
        # Scan for values that look like return addresses (in ripgrep's __TEXT or libraries)
        for i in range(0, len(stack_data), 8):
            val = struct.unpack('<Q', stack_data[i:i+8])[0]
            if val < 0x1000:
                continue
            # Check if it's in ripgrep
            in_rg = False
            for segname, svmaddr, svmsize in rg_segs:
                slid_addr = svmaddr + rg_slide
                if slid_addr <= val < slid_addr + svmsize:
                    print(f"  rsp+{i:#x}: {val:#018x} -> ripgrep {segname}+{val-slid_addr:#x}")
                    in_rg = True
                    break
            if not in_rg and 0x7f0000000000 <= val <= 0x7fffffffffff:
                # Could be a library address
                for vaddr2, filesz2, _ in load_segments:
                    if vaddr2 <= val < vaddr2 + filesz2:
                        print(f"  rsp+{i:#x}: {val:#018x} -> library at {vaddr2:#x}+{val-vaddr2:#x}")
                        break
        break
