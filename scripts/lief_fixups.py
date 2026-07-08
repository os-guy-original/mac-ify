#!/usr/bin/env python3
"""Use LIEF to list all chained fixups for sqlite3."""
import lief

FILE = "/home/z/my-project/mac-ify/tests/real/sqlite3_macos"
fat = lief.MachO.parse(FILE)
binary = fat[0]

print("=== Segments ===")
for seg in binary.segments:
    print(f"  {seg.name}: vmaddr=0x{seg.virtual_address:x} vmsize=0x{seg.virtual_size:x} fileoff=0x{seg.file_offset:x} filesize=0x{seg.file_size:x}")

print("\n=== Sections ===")
for sec in binary.sections:
    print(f"  {sec.segment.name}.{sec.name}: vmaddr=0x{sec.virtual_address:x} size=0x{sec.size:x}")

print("\n=== Chained fixups ===")
if binary.has_dyld_chained_fixups:
    cmd = binary.dyld_chained_fixups
    print(f"  fixups_version: {cmd.fixups_version}")
    print(f"  starts_offset: 0x{cmd.starts_offset:x}")
    print(f"  imports_offset: 0x{cmd.imports_offset:x}")
    print(f"  symbols_offset: 0x{cmd.symbols_offset:x}")
    print(f"  imports_count: {cmd.imports_count}")
    # Try different attributes
    print(f"  attrs: {[a for a in dir(cmd) if not a.startswith('_')]}")
else:
    print("  No chained fixups")
