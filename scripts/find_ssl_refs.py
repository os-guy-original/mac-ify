#!/usr/bin/env python3
"""Search for ANY reference to SSL_CTX_new_ex address in the binary."""
import lief, struct

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]

# SSL_CTX_new_ex is at 0x1001a4990
# Search for this address in all sections
target = 0x1001a4990
target_bytes = struct.pack('<Q', target)
target_bytes4 = struct.pack('<I', target & 0xFFFFFFFF)

for sec in b.sections:
    data = bytes(sec.content)
    # Search for 8-byte address
    idx = 0
    while True:
        idx = data.find(target_bytes, idx)
        if idx == -1:
            break
        print(f'  8-byte ref in {sec.segment.name}.{sec.name} at +0x{idx:x} (static 0x{sec.virtual_address+idx:x})')
        idx += 1
    # Search for 4-byte address (lower 32 bits)
    idx = 0
    while True:
        idx = data.find(target_bytes4, idx)
        if idx == -1:
            break
        # Check if the next 4 bytes are 0x00000001 (upper 32 bits)
        if idx + 4 < len(data):
            upper = struct.unpack_from('<I', data, idx + 4)[0]
            if upper == 1:
                print(f'  4+4-byte ref in {sec.segment.name}.{sec.name} at +0x{idx:x} (static 0x{sec.virtual_address+idx:x})')
        idx += 1

# Also search for SSL_CTX_new (0x1001a5020)
target2 = 0x1001a5020
target2_bytes = struct.pack('<Q', target2)
for sec in b.sections:
    data = bytes(sec.content)
    idx = 0
    while True:
        idx = data.find(target2_bytes, idx)
        if idx == -1:
            break
        print(f'  SSL_CTX_new ref in {sec.segment.name}.{sec.name} at +0x{idx:x} (static 0x{sec.virtual_address+idx:x})')
        idx += 1
