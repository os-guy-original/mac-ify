#!/usr/bin/env python3
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

# ssl_load_ciphers at 0x1005a6e40
off = 0x1005a6e40 - text_base
print('=== ssl_load_ciphers ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x200], 0x1005a6e40)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 50:
        break
