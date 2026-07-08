#!/usr/bin/env python3
"""Find ALL LEA rip+disp32 instructions in __TEXT that target the error string."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

targets = [0x1005d15c5, 0x1005d2389]

# Scan more broadly: any REX.W LEA with RIP-relative addressing
# REX.W = 0x48 or 0x4C (with REX.R for r8-r15)
# LEA = 0x8D
# ModRM with mod=00, rm=101 = RIP-relative
for target in targets:
    print(f'\nSearching for LEA to 0x{target:x}:')
    for off in range(0, 0x701000 - 7):
        # Check for REX prefix (0x48-0x4F)
        if 0x48 <= data[off] <= 0x4F and data[off+1] == 0x8D:
            modrm = data[off+2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from('<i', data, off + 3)[0]
                target_addr = 0x100000000 + off + 7 + disp
                if target_addr == target:
                    print(f'  LEA at file 0x{off:x} (static 0x{0x100000000+off:x})')
                    # Show surrounding bytes for context
                    print(f'    bytes: {data[off:off+7].hex()}')

# Also check: maybe the string is loaded indirectly via a Rust &'static str
# which is (ptr, len) tuple. Search for the 8-byte address
for target in targets:
    target_bytes = struct.pack('<Q', target)
    idx = 0
    while True:
        idx = data.find(target_bytes, idx)
        if idx == -1:
            break
        if idx < 0x701000:
            seg = '__TEXT'
        elif idx < 0x752000:
            seg = '__DATA_CONST'
        elif idx < 0x757000:
            seg = '__DATA'
        else:
            seg = '__LINKEDIT'
        print(f'  0x{target:x} as 8-byte at file 0x{idx:x} (static 0x{0x100000000+idx:x}) in {seg}')
        idx += 1
