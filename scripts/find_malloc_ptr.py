#!/usr/bin/env python3
import lief, struct
fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
# CRYPTO_zalloc at 0x1005b1250
# mov rax, [rip + 0x1f8396] at 0x1005b1263, next ins at 0x1005b126a
# target = 0x1005b126a + 0x1f8396 = 0x1007a9600
target = 0x1005b126a + 0x1f8396
print(f'Global at 0x{target:x}')
# Find what section it's in
for sec in b.sections:
    if sec.virtual_address <= target < sec.virtual_address + sec.size:
        off = target - sec.virtual_address
        data = bytes(sec.content)
        val = struct.unpack_from('<Q', data, off)[0]
        print(f'  in {sec.segment.name}.{sec.name}, raw value = 0x{val:016x}')
        break
# Find symbol
for sym in b.symbols:
    if sym.value == target:
        print(f'  Symbol: {sym.name}')
        break
