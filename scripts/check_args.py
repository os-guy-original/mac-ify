#!/usr/bin/env python3
"""Disassemble around 0x1000a6025 (SSL_CTX_new_ex call) to see args."""
import lief, capstone

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
text = None
for sec in b.sections:
    if sec.name == '__text':
        text = sec; break
text_data = bytes(text.content)
text_base = text.virtual_address
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Disassemble from 0x1000a600f to 0x1000a6030
off = 0x1000a600f - text_base
print('=== Before SSL_CTX_new_ex call ===')
for ins in md.disasm(text_data[off:off+0x30], 0x1000a600f):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if ins.address >= 0x1000a6028:
        break
