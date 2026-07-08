#!/usr/bin/env python3
"""Find ALL references to string 0x1005eb493 (SSL_CTX_new_ex) in the binary."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

# Search for the 8-byte address 0x1005eb493
target = 0x1005eb493
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
    print(f'  8-byte ref at file 0x{idx:x} (static 0x{0x100000000+idx:x}) in {seg}')
    idx += 1

# Also search for LEA rip+disp32 patterns (E8 or 48 8D xx)
# 48 8D 05 = lea rax, [rip+disp32]
# 48 8D 0D = lea rcx, [rip+disp32]
# 48 8D 15 = lea rdx, [rip+disp32]
# 48 8D 35 = lea rsi, [rip+disp32]
# 48 8D 3D = lea rdi, [rip+disp32]
# The disp32 is relative to the NEXT instruction (offset + 7)

# Scan for LEA rip+disp32 that targets 0x1005eb493
for off in range(0, 0x701000 - 7):
    if data[off] == 0x48 and data[off+1] == 0x8D:
        modrm = data[off+2]
        if (modrm & 0xC7) == 0x05:  # mod=00, rm=101 (RIP-relative)
            disp = struct.unpack_from('<i', data, off + 3)[0]
            target_addr = 0x100000000 + off + 7 + disp
            if target_addr == target:
                print(f'  LEA at file 0x{off:x} (static 0x{0x100000000+off:x})')
