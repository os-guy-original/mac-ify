#!/usr/bin/env python3
"""Find what calls SSL_CTX_new_ex by searching for the error string more broadly.
The string might be in a Rust const data struct as (ptr, len)."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

# The strings are at 0x1005d15c5 and 0x1005d2389
# In Rust, a &str is (ptr, len). So search for the 8-byte address followed by
# the 8-byte length (26 for "could not create a context")
targets = {0x1005d15c5: 26, 0x1005d2389: 26}

for target, length in targets.items():
    target_bytes = struct.pack('<Q', target)
    length_bytes = struct.pack('<Q', length)
    combined = target_bytes + length_bytes
    idx = 0
    while True:
        idx = data.find(combined, idx)
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
        print(f'  (ptr=0x{target:x}, len={length}) at file 0x{idx:x} (static 0x{0x100000000+idx:x}) in {seg}')
        idx += 1

# Also try: the string might be loaded via a global pointer
# Search for the address as a standalone 8-byte value
for target in targets:
    target_bytes = struct.pack('<Q', target)
    idx = 0
    while True:
        idx = data.find(target_bytes, idx)
        if idx == -1:
            break
        if idx < 0x757000:  # Skip LINKEDIT
            print(f'  0x{target:x} as 8-byte at file 0x{idx:x} (static 0x{0x100000000+idx:x})')
        idx += 1
