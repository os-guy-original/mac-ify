#!/usr/bin/env python3
import struct

with open('/home/z/my-project/mac-ify/tests/real/wget_macos', 'rb') as f:
    data = f.read()

fixups_off = 389120
# From mach-o/loader.h:
# struct dyld_chained_fixups_header {
#     uint32_t    fixups_version;    // 0
#     uint32_t    starts_offset;     // =4
#     uint32_t    imports_offset;    // =8
#     uint32_t    symbols_offset;    // =12
#     uint32_t    imports_count;     // =16
#     uint32_t    symbols_length;    // =20
# };
hdr = struct.unpack('<IIIIII', data[fixups_off:fixups_off+24])
print(f'fixups_version={hdr[0]} starts_offset={hdr[1]} imports_offset={hdr[2]} symbols_offset={hdr[3]} imports_count={hdr[4]} symbols_length={hdr[5]}')

starts_base = fixups_off + hdr[1]
# struct dyld_chained_starts_in_image {
#     uint32_t    starts_count;       // =0
#     uint32_t    chain_starts[];     // =4
# };
starts_count = struct.unpack('<I', data[starts_base:starts_base+4])[0]
print(f'starts_count={starts_count}')
starts = struct.unpack(f'<{starts_count}I', data[starts_base+4:starts_base+4+starts_count*4])
print(f'starts: {[hex(s) for s in starts]}')

for seg_idx, s in enumerate(starts):
    if s == 0:
        print(f'seg {seg_idx}: no fixups')
        continue
    seg_starts = starts_base + s
    # struct dyld_chained_starts_in_segment {
#     uint32_t    size;               // =0 (size of this struct + page_starts)
#     uint16_t    page_size;          // =4
#     uint16_t    pointer_format;     // =6
#     uint64_t    segment_offset;     // =8
#     uint32_t    max_valid_pointer;  // =16
#     uint16_t    page_count;         // =20
#     uint16_t    page_start[];       // =22
# };
    seg_size = struct.unpack('<I', data[seg_starts:seg_starts+4])[0]
    page_size = struct.unpack('<H', data[seg_starts+4:seg_starts+6])[0]
    ptr_format = struct.unpack('<H', data[seg_starts+6:seg_starts+8])[0]
    seg_offset = struct.unpack('<Q', data[seg_starts+8:seg_starts+16])[0]
    max_valid = struct.unpack('<I', data[seg_starts+16:seg_starts+20])[0]
    page_count = struct.unpack('<H', data[seg_starts+20:seg_starts+22])[0]
    print(f'seg {seg_idx}: size={seg_size} page_size={page_size} ptr_format={ptr_format} page_count={page_count} seg_offset=0x{seg_offset:x}')
    if page_count > 100:
        print(f'  page_count too large, skipping')
        continue
    page_starts = struct.unpack(f'<{page_count}H', data[seg_starts+22:seg_starts+22+page_count*2])
    for pi, ps in enumerate(page_starts):
        if ps == 0xFFFF:
            print(f'  page {pi}: NONE')
        elif ps & 0x8000:
            print(f'  page {pi}: chain start to page {ps & 0x7FFF}')
        else:
            print(f'  page {pi}: start offset {ps} (0x{ps:x})')
