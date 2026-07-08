#!/usr/bin/env python3
"""Disassemble ssl_evp_cipher_fetch to see why it returns NULL."""
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

# ssl_evp_cipher_fetch at 0x1001aa180
off = 0x1001aa180 - text_base
print('=== ssl_evp_cipher_fetch ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x200], 0x1001aa180)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 40:
        break
