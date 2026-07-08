#!/usr/bin/env python3
"""Disassemble ossl_rand_pool_init."""
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

off = 0x100536670 - text_base
print('=== ossl_rand_pool_init ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x80], 0x100536670)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 20:
        break
