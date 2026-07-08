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
syms = sorted([(s.value, s.name) for s in b.symbols if s.value], key=lambda x: x[0])

# CRYPTO_zalloc at 0x1005b1250
off = 0x1005b1250 - text_base
print('=== CRYPTO_zalloc ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x80], 0x1005b1250)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if ins.mnemonic == 'call':
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                t = op.imm
                sname = '?'
                for v, n in syms:
                    if v == t:
                        sname = n
                        break
                print(f'    -> {sname}')
                break
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 15:
        break
