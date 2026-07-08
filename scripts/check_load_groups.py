#!/usr/bin/env python3
"""Disassemble ssl_load_groups and ssl_load_sigalgs."""
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

syms = sorted([(s.value, s.name) for s in b.symbols if s.value], key=lambda x: x[0])

# ssl_load_groups at 0x1001b2290
off = 0x1001b2290 - text_base
print('=== ssl_load_groups ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x100], 0x1001b2290)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 20:
        break

# ssl_load_sigalgs at 0x1001b2310
print()
off = 0x1001b2310 - text_base
print('=== ssl_load_sigalgs ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x100], 0x1001b2310)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 20:
        break
