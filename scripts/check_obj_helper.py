#!/usr/bin/env python3
"""Disassemble the function at 0x100426420 (called by OBJ_nid2sn)."""
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

off = 0x100426420 - text_base
print('=== 0x100426420 (OBJ_nid2obj helper) ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x100], 0x100426420)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 30:
        break

# Find symbol
syms = sorted([(s.value, s.name) for s in b.symbols if s.value], key=lambda x: x[0])
exact = [(v,n) for v,n in syms if v == 0x100426420]
if exact:
    print(f'\nSymbol: {exact[0][1]}')
