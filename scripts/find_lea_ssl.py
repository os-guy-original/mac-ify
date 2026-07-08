#!/usr/bin/env python3
"""Find LEA instructions that load the string 'SSL_CTX_new_ex' address."""
import lief, capstone, struct

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

# The string "SSL_CTX_new_ex" is at static 0x1005eb493
# Find LEAs that reference this address
target = 0x1005eb493
for ins in md.disasm(text_data, text_base):
    if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                addr = ins.address + ins.size + op.mem.disp
                if addr == target:
                    syms = sorted([(s.value, s.name) for s in b.symbols if s.value], reverse=True)
                    for v, n in syms:
                        if v <= ins.address:
                            print(f'  LEA "SSL_CTX_new_ex" at 0x{ins.address:x} in {n}')
                            break
                    break
