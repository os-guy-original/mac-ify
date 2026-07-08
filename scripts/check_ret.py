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

# ssl_load_ciphers at 0x1005a6e40 — find the return value
off = 0x1005a6e40 - text_base
insns = list(md.disasm(text_data[off:off+0x800], 0x1005a6e40))
# Find all 'ret' and the instructions before them
for i, ins in enumerate(insns):
    if 'ret' in ins.mnemonic and i > 0:
        # Print 10 instructions before ret
        start = max(0, i-10)
        print(f'=== ret at 0x{ins.address:x} ===')
        for j in range(start, i+1):
            print(f'  0x{insns[j].address:x}: {insns[j].bytes.hex():<22s} {insns[j].mnemonic} {insns[j].op_str}')
        print()
