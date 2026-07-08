#!/usr/bin/env python3
"""Disassemble the function at 0x100484aa0 (sk_reserve or similar)."""
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
exact = [(v,n) for v,n in syms if v == 0x100484aa0]
if exact:
    print(f'0x100484aa0 = {exact[0][1]}')
else:
    print('0x100484aa0 = ?')

off = 0x100484aa0 - text_base
print('\n=== 0x100484aa0 ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x150], 0x100484aa0)):
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
    if i > 40:
        break
