#!/usr/bin/env python3
"""Find what calls SSL_CTX_new_ex by searching for the error string."""
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

# Find LEA to the "could not create a context" string
# The string is at... let me find it
import struct
cstring_sec = None
for sec in b.sections:
    if sec.name == '__cstring':
        cstring_sec = sec; break
cstr_data = bytes(cstring_sec.content)
cstr_base = cstring_sec.virtual_address

target_str = b'could not create a context\x00'
idx = cstr_data.find(target_str)
if idx >= 0:
    str_addr = cstr_base + idx
    print(f'String at 0x{str_addr:x}')

    # Find LEAs to this string
    for ins in md.disasm(text_data, text_base):
        if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    addr = ins.address + ins.size + op.mem.disp
                    if addr == str_addr:
                        syms = sorted([(s.value, s.name) for s in b.symbols if s.value], reverse=True)
                        for v, n in syms:
                            if v <= ins.address:
                                print(f'  LEA at 0x{ins.address:x} in {n}')
                                break
                        break
