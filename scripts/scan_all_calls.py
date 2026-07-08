#!/usr/bin/env python3
"""Find calls to SSL_CTX_new_ex (0x1001a4990) using a comprehensive scan."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

# Scan for E8 rel32 where target = 0x1001a4990
target = 0x1001a4990
count = 0
for off in range(0, len(data) - 5):
    if data[off] == 0xE8:
        rel = struct.unpack_from('<i', data, off + 1)[0]
        # File offset to static address: static = file_offset + 0x100000000
        # target = next_insn_static + rel = (0x100000000 + off + 5) + rel
        t = (0x100000000 + off + 5 + rel) & 0xFFFFFFFF
        if t == target:
            print(f'  E8 call to SSL_CTX_new_ex at file 0x{off:x} (static 0x{0x100000000+off:x})')
            count += 1

# Also scan for E9 (jmp)
for off in range(0, len(data) - 5):
    if data[off] == 0xE9:
        rel = struct.unpack_from('<i', data, off + 1)[0]
        t = (0x100000000 + off + 5 + rel) & 0xFFFFFFFF
        if t == target:
            print(f'  E9 jmp to SSL_CTX_new_ex at file 0x{off:x} (static 0x{0x100000000+off:x})')

# Also check for FF 15 (call [rip+disp32]) — indirect call through GOT
for off in range(0, len(data) - 6):
    if data[off] == 0xFF and data[off+1] == 0x15:
        disp = struct.unpack_from('<i', data, off + 2)[0]
        # The GOT entry address = static_addr_of_next_insn + disp
        got_addr = (0x100000000 + off + 6 + disp) & 0xFFFFFFFF
        # Check if this GOT entry contains 0x1001a4990
        # GOT is in __DATA_CONST.__got or __DATA
        # Read the 8 bytes at the GOT address
        got_file_off = got_addr - 0x100000000
        if 0 <= got_file_off < len(data) - 8:
            val = struct.unpack_from('<Q', data, got_file_off)[0]
            if val == target:
                print(f'  FF 15 indirect call via GOT at 0x{0x100000000+off:x}, GOT entry at 0x{got_addr:x}')

print(f'\nTotal E8 calls found: {count}')
