#!/usr/bin/env python3
"""Search for call instructions (E8 rel32) that target SSL_CTX_new."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

# __TEXT starts at file offset 0, static 0x100000000
# SSL_CTX_new_ex = 0x1001a4990, file offset = 0x1a4990
# SSL_CTX_new = 0x1001a5020, file offset = 0x1a5020

# Scan for E8 XX XX XX XX where the target is one of these
# E8 rel32: target = address_of_next_instruction + rel32
# address_of_next_instruction = file_offset + 5

targets = {0x1001a4990: 'SSL_CTX_new_ex', 0x1001a5020: 'SSL_CTX_new'}

# __TEXT segment: file 0 to 0x701000
for off in range(0, 0x701000 - 5):
    if data[off] == 0xE8:
        rel = struct.unpack_from('<i', data, off + 1)[0]
        target = (0x100000000 + off + 5 + rel) & 0xFFFFFFFF
        if target in targets:
            print(f'  E8 call to {targets[target]} at file 0x{off:x} (static 0x{0x100000000+off:x})')

# Also check for FF 15 (call [rip+disp32]) which is indirect
# This would be used if calling through GOT
# But SSL_CTX_new is defined locally, so it should be direct
