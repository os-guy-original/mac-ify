#!/usr/bin/env python3
"""Find LEA references to 0x1005d15c5 and 0x1005d2389."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

targets = [0x1005d15c5, 0x1005d2389]

for target in targets:
    print(f'\nSearching for LEA to 0x{target:x}:')
    # Scan for 48 8D xx (LEA r64, [rip+disp32])
    for off in range(0, 0x701000 - 7):
        if data[off] == 0x48 and data[off+1] == 0x8D:
            modrm = data[off+2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from('<i', data, off + 3)[0]
                target_addr = 0x100000000 + off + 7 + disp
                if target_addr == target:
                    print(f'  LEA at file 0x{off:x} (static 0x{0x100000000+off:x})')
