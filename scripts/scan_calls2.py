#!/usr/bin/env python3
"""Search for call instructions (E8 rel32) that target SSL_CTX_new.
Also search for JMP rel32 (E9)."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

targets = {0x1001a4990: 'SSL_CTX_new_ex', 0x1001a5020: 'SSL_CTX_new'}

# Scan __TEXT (file 0 to ~0x701000)
count = 0
for off in range(0, 0x701000 - 5):
    b = data[off]
    if b == 0xE8 or b == 0xE9:
        rel = struct.unpack_from('<i', data, off + 1)[0]
        target = (0x100000000 + off + 5 + rel) & 0xFFFFFFFF
        if target in targets:
            kind = 'call' if b == 0xE8 else 'jmp'
            print(f'  {kind} to {targets[target]} at static 0x{0x100000000+off:x}')
            count += 1

print(f'\nTotal: {count}')

# Also check: maybe the addresses are wrong. Verify by reading the first
# bytes at the expected file offsets
print(f'\nVerification:')
print(f'  At file 0x1a4990 (SSL_CTX_new_ex): {data[0x1a4990:0x1a499a].hex()}')
print(f'  At file 0x1a5020 (SSL_CTX_new): {data[0x1a5020:0x1a502a].hex()}')
# push rbp = 55, so should start with 55
