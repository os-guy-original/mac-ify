#!/usr/bin/env python3
"""Find LEA to 0x1005d15c0 (SSL: could not create a context: %s)."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

target = 0x1005d15c0
print(f'Searching for LEA to 0x{target:x}:')
for off in range(0, 0x701000 - 7):
    if 0x48 <= data[off] <= 0x4F and data[off+1] == 0x8D:
        modrm = data[off+2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', data, off + 3)[0]
            target_addr = 0x100000000 + off + 7 + disp
            if target_addr == target:
                print(f'  LEA at file 0x{off:x} (static 0x{0x100000000+off:x})')

# Also search as 8-byte pointer
target_bytes = struct.pack('<Q', target)
idx = 0
while True:
    idx = data.find(target_bytes, idx)
    if idx == -1:
        break
    if idx < 0x757000:
        print(f'  8-byte ptr at file 0x{idx:x} (static 0x{0x100000000+idx:x})')
    idx += 1
