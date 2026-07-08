#!/usr/bin/env python3
"""Disassemble ciphersuite_cb from OPENSSL_sk_push to the return."""
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

# Continue from 0x10019a7ea (OPENSSL_sk_push call)
off = 0x10019a7ea - text_base
print('=== ciphersuite_cb after OPENSSL_sk_push ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x60], 0x10019a7ea)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 20:
        break
