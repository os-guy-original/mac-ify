#!/usr/bin/env python3
"""Disassemble around a static offset in the sqlite3 Mach-O."""
import sys
import lief
import capstone

# Static offset of crash rip — file offset 0x7b259 in __TEXT (which starts at file 0)
# Actually: rip is __TEXT_base + 0x7b259
FILE = "/home/z/my-project/mac-ify/tests/real/sqlite3_macos"
STATIC_RIP = 0x100000000 + 0x7b259  # static address of crash

# Disassemble window
WINDOW_BEFORE = 0x80
WINDOW_AFTER  = 0x100

def main():
    fat = lief.MachO.parse(FILE)
    if not fat or len(fat) == 0:
        print("Failed to parse")
        return
    binary = fat[0]
    # Get the text section
    text = None
    for sec in binary.sections:
        if sec.name == "__text":
            text = sec
            break
    if not text:
        print("No __text section")
        return
    text_base = text.virtual_address  # static
    text_data = bytes(text.content)
    print(f"__text @ static=0x{text_base:x} size=0x{len(text_data):x}")
    # Find offset in __text
    off = STATIC_RIP - text_base
    print(f"crash offset in __text = 0x{off:x}")
    start = max(0, off - WINDOW_BEFORE)
    end = min(len(text_data), off + WINDOW_AFTER)
    chunk = text_data[start:end]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    for ins in md.disasm(chunk, text_base + start):
        marker = " <-- CRASH HERE" if ins.address == STATIC_RIP else ""
        print(f"  0x{ins.address:x}:  {ins.bytes.hex():<24s} {ins.mnemonic} {ins.op_str}{marker}")

if __name__ == "__main__":
    main()
