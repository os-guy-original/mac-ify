#!/usr/bin/env python3
import lief, capstone, sys

b = lief.parse('/home/z/.macify/bin/bash')
for sec in b.sections:
    if sec.name == '__text':
        text_sec = sec; break

data = bytes(text_sec.content)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x5074
target_offset = target - text_sec.virtual_address
start = max(0, target_offset - 80)
end = min(len(data), target_offset + 20)
for ins in md.disasm(data[start:end], text_sec.virtual_address + start):
    m = ' <-- EXIT' if ins.address == target else ''
    print('0x%x: %s %s%s' % (ins.address, ins.mnemonic, ins.op_str, m))
