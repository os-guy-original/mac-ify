#!/usr/bin/env python3
"""Inspect what's at a given static address in the sqlite3 Mach-O."""
import sys
import lief
import capstone

FILE = "/home/z/my-project/mac-ify/tests/real/sqlite3_macos"

# call [rip + 0xd74d1] at instruction 0x10007b221
# Next instruction at 0x10007b227
# Target = 0x10007b227 + 0xd74d1
CALL_INSN_ADDR = 0x10007b221
NEXT_INSN_ADDR = 0x10007b227
DISP = 0xd74d1
GOT_ADDR = NEXT_INSN_ADDR + DISP
print(f"Call target address: 0x{GOT_ADDR:x}")

def main():
    fat = lief.MachO.parse(FILE)
    binary = fat[0]
    
    # What section does GOT_ADDR fall in?
    for sec in binary.sections:
        sa = sec.virtual_address
        sz = sec.size
        if sa <= GOT_ADDR < sa + sz:
            print(f"GOT addr in section: {sec.segment.name}.{sec.name} (static 0x{sa:x}, size 0x{sz:x})")
            off = GOT_ADDR - sa
            print(f"  offset in section = 0x{off:x}")
            data = bytes(sec.content)
            # Read 8 bytes at offset
            if off + 8 <= len(data):
                val = int.from_bytes(data[off:off+8], 'little')
                print(f"  8 bytes at offset: 0x{val:x}")
            break
    
    # Print all chained fixups
    print("\n=== Chained fixups ===")
    if binary.has_dyld_chained_fixups:
        cmd = binary.dyld_chained_fixups
        for seg in cmd.segments:
            for fixup in seg.fixups:
                target = fixup.target
                addr = fixup.address
                # target is an int (ordinal) or str (symbol name)
                if isinstance(target, str):
                    print(f"  fixup @ 0x{addr:x} -> symbol '{target}'")
                else:
                    print(f"  fixup @ 0x{addr:x} -> ordinal {target}")
    else:
        print("  No chained fixups")
    
    # Print __got section content (first 32 entries)
    print("\n=== __got section ===")
    for sec in binary.sections:
        if sec.name == "__got":
            data = bytes(sec.content)
            print(f"  section {sec.segment.name}.{sec.name} @ static 0x{sec.virtual_address:x} size 0x{sec.size:x}")
            for i in range(0, min(len(data), 0x4a8), 8):
                val = int.from_bytes(data[i:i+8], 'little')
                print(f"  +0x{i:03x} (static 0x{sec.virtual_address+i:x}): 0x{val:x}")
            break
    
    # Print all symbols
    print("\n=== Imports ===")
    for sym in binary.imported_symbols:
        print(f"  {sym.name}")

if __name__ == "__main__":
    main()
