#!/usr/bin/env python3
import lief, capstone, sys, os
os.environ['LIEF_LOGGING_LEVEL'] = 'critical'

b = lief.parse(sys.argv[1] if len(sys.argv) > 1 else '/home/z/my-project/mac-ify/tests/real/rclone_macos')
for sec in b.sections:
    if sec.name == '__text':
        text_sec = sec
        break

data = bytes(text_sec.content)
target = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x100098527
target_offset = target - text_sec.virtual_address

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
start = max(0, target_offset - 40)
end = min(len(data), target_offset + 16)
chunk = data[start:end]
base = text_sec.virtual_address + start
for ins in md.disasm(chunk, base):
    marker = ' <-- CRASH' if ins.address == target else ''
    print(f'  0x{ins.address:x}: {ins.bytes.hex():20s} {ins.mnemonic} {ins.op_str}{marker}')
