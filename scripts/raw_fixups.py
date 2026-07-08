#!/usr/bin/env python3
"""Examine raw chained fixup bytes."""
import lief

FILE = "/home/z/my-project/mac-ify/tests/real/sqlite3_macos"
fat = lief.MachO.parse(FILE)
b = fat[0]

# Read the entire file
with open(FILE, 'rb') as f:
    file_data = f.read()

# Find chained fixups load command
for cmd in b.commands:
    if hasattr(cmd.command, 'data_offset'):
        # generic
        pass

cmd = b.dyld_chained_fixups
print(f"Chained fixups:")
print(f"  fixups_version: {cmd.fixups_version}")
print(f"  starts_offset: 0x{cmd.starts_offset:x}")
print(f"  imports_offset: 0x{cmd.imports_offset:x}")
print(f"  symbols_offset: 0x{cmd.symbols_offset:x}")
print(f"  imports_count: {cmd.imports_count}")
print(f"  imports_format: {cmd.imports_format}")
print(f"  symbols_format: {cmd.symbols_format}")

# Find the load command to get the file offset of the chained fixups data
# It's stored as a load command with type LC_DYLD_CHAINED_FIXUPS (0x80000028)
print("\n=== All load commands ===")
for load_cmd in b.commands:
    lc = load_cmd.command
    cmd_type = lc.cmd
    print(f"  cmd={cmd_type} size={lc.cmdsize}")

# Read raw fixup header from file
# Try to find by scanning load commands
for load_cmd in b.commands:
    lc = load_cmd.command
    if hasattr(lc, 'cmd') and lc.cmd == lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS:
        # data offset is relative to file start
        print(f"\nRaw fixup data:")
        # The struct is dyld_chained_fixups_header:
        # uint32_t fixups_version;
        # uint32_t starts_offset;
        # uint32_t imports_offset;
        # uint32_t symbols_offset;
        # uint32_t imports_count;
        # uint32_t imports_format;
        # uint32_t symbols_format;
        # uint8_t  starts[]; // until starts_offset+... 
        dataoff = lc.dataoff
        datasize = lc.datasize
        fixup_data = file_data[dataoff:dataoff+datasize]
        print(f"  total fixup data: {datasize} bytes")
        # Print header
        import struct
        fv, so, io, so2, ic, ifo, sf = struct.unpack_from('<7I', fixup_data, 0)
        print(f"  header: fv={fv} starts_off=0x{so:x} imports_off=0x{io:x} symbols_off=0x{so2:x} imports_count={ic} imports_format={ifo} symbols_format={sf}")
        # Print starts
        starts_data = fixup_data[so:]
        starts_count = struct.unpack_from('<I', starts_data, 0)[0]
        starts_offsets = struct.unpack_from(f'<{starts_count}I', starts_data, 4)
        print(f"  starts_in_image: count={starts_count}, seg_offsets={[hex(o) for o in starts_offsets]}")
        # For each segment
        for seg_idx, off in enumerate(starts_offsets):
            if off == 0:
                print(f"  seg {seg_idx}: no fixups (offset=0)")
                continue
            print(f"  seg {seg_idx}: starts at offset 0x{off:x} within starts_data")
            seg_data = starts_data[off:]
            size, page_size, ptr_format, seg_offset_lo, seg_offset_hi, max_valid, page_count = struct.unpack_from('<IHHQIH', seg_data, 0)
            seg_offset = seg_offset_lo | (seg_offset_hi << 32)
            print(f"    size=0x{size:x} page_size={page_size} ptr_format={ptr_format} seg_offset=0x{seg_offset:x} max_valid=0x{max_valid:x} page_count={page_count}")
            page_starts = struct.unpack_from(f'<{page_count}H', seg_data, 22)
            print(f"    page_starts: {[hex(p) for p in page_starts]}")
        # Print imports
        print(f"\n  Imports:")
        for i in range(ic):
            imp_off = io + i * 4
            imp_raw = struct.unpack_from('<I', fixup_data, imp_off)[0]
            lib_ord = imp_raw & 0xFF
            name_off = (imp_raw >> 8) & 0xFFFFFF  # actually different
            # The format depends on imports_format
            # For DYLD_CHAINED_IMPORT: 8 bits lib_ordinal, 24 bits name_offset
            # For DYLD_CHAINED_IMPORT_ADDEND: 8 bits lib_ordinal, 24 bits name_offset, 32 bits addend
            # For DYLD_CHAINED_IMPORT_ADDEND64: similar
            print(f"    [{i}] raw=0x{imp_raw:08x} lib_ord={lib_ord} name_off=0x{name_off:x}")
        # Print symbols
        print(f"\n  Symbol names:")
        sym_data = fixup_data[so2:]
        # Names are null-terminated strings
        off_in_sym = 0
        for i in range(20):  # print first 20
            end = sym_data.find(b'\x00', off_in_sym)
            if end == -1: break
            name = sym_data[off_in_sym:end].decode('utf-8', errors='replace')
            print(f"    +0x{off_in_sym:x}: '{name}'")
            off_in_sym = end + 1
        break
