#!/usr/bin/env python3
"""Search for SSL_CTX_new's address stored as a function pointer (8-byte value)."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

targets = [0x1001a4990, 0x1001a5020]

for target in targets:
    target_bytes = struct.pack('<Q', target)
    idx = 0
    while True:
        idx = data.find(target_bytes, idx)
        if idx == -1:
            break
        # Determine which segment this is in
        if idx < 0x701000:
            seg = '__TEXT'
        elif idx < 0x752000:
            seg = '__DATA_CONST'
        elif idx < 0x757000:
            seg = '__DATA'
        else:
            seg = '__LINKEDIT'
        print(f'  0x{target:x} found at file 0x{idx:x} (static 0x{0x100000000+idx:x}) in {seg}')
        idx += 1

# Also search for the address with a slide (rebased)
# If the binary has been loaded, the address would be target + slide
# But we're reading the file, so it should be the static address
# Let's also check if it appears as a 4-byte value (lower 32 bits)
for target in targets:
    target_bytes4 = struct.pack('<I', target & 0xFFFFFFFF)
    idx = 0
    count = 0
    while True:
        idx = data.find(target_bytes4, idx)
        if idx == -1:
            break
        count += 1
        idx += 1
    print(f'  0x{target:x} as 4-byte: found {count} times')
