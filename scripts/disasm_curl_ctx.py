#!/usr/bin/env python3
"""Disassemble Curl_ossl_ctx_init around the error string LEA at 0x1000a6201."""
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

# Disassemble from 0x1000a5ec0 to 0x1000a6300
off = 0x1000a5ec0 - text_base
for i, ins in enumerate(md.disasm(text_data[off:off+0x500], 0x1000a5ec0)):
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
            elif op.type == capstone.x86.X86_OP_REG:
                print(f'  0x{ins.address:x}: call {ins.op_str}  *** INDIRECT ***')
                break
    elif ins.mnemonic == 'lea' and 'rip' in ins.op_str:
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                addr = ins.address + ins.size + op.mem.disp
                print(f'  0x{ins.address:x}: lea {ins.op_str}  (-> 0x{addr:x})')
                break
    elif ins.mnemonic in ('test', 'cmp'):
        print(f'  0x{ins.address:x}: {ins.mnemonic} {ins.op_str}')
    elif ins.mnemonic in ('je', 'jne', 'jz', 'jnz') and 'rip' not in ins.op_str:
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                print(f'  0x{ins.address:x}: {ins.mnemonic} 0x{op.imm:x}')
                break
    if ins.address > 0x1000a6250:
        break
