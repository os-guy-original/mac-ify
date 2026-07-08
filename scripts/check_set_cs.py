#!/usr/bin/env python3
"""Disassemble set_ciphersuites (0x100196df0) to find the exact failure."""
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

# set_ciphersuites at 0x100196df0
off = 0x100196df0 - text_base
print('=== set_ciphersuites ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x200], 0x100196df0)):
    if ins.mnemonic == 'call':
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                t = op.imm
                sname = '?'
                for v, n in syms:
                    if v == t:
                        sname = n
                        break
                print(f'  0x{ins.address:x}: call {sname} (0x{t:x})')
                break
    elif ins.mnemonic in ('test', 'cmp'):
        print(f'  0x{ins.address:x}: {ins.mnemonic} {ins.op_str}')
    elif ins.mnemonic in ('je', 'jne', 'jz', 'jnz', 'jle', 'jge') and 'rip' not in ins.op_str:
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                print(f'  0x{ins.address:x}: {ins.mnemonic} 0x{op.imm:x}')
                break
    elif ins.mnemonic == 'mov' and 'edi' in ins.op_str and '0x' in ins.op_str:
        print(f'  0x{ins.address:x}: {ins.mnemonic} {ins.op_str}  *** sets error reason ***')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 50:
        break
