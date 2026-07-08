#!/usr/bin/env python3
import lief, struct
fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
# malloc_impl at 0x1005b11a0
# mov rax, [rip + 0x1f8446] at 0x1005b11b3, next ins at 0x1005b11ba
target = 0x1005b11ba + 0x1f8446
print(f'Global at 0x{target:x}')
for sec in b.sections:
    if sec.virtual_address <= target < sec.virtual_address + sec.size:
        off = target - sec.virtual_address
        data = bytes(sec.content)
        val = struct.unpack_from('<Q', data, off)[0]
        print(f'  in {sec.segment.name}.{sec.name}, raw value = 0x{val:016x}')
        break
for sym in b.symbols:
    if sym.value == target:
        print(f'  Symbol: {sym.name}')
        break
