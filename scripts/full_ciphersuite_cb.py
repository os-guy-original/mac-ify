#!/usr/bin/env python3
"""Disassemble ciphersuite_cb to find the OPENSSL_sk_push call and its args."""
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

# ciphersuite_cb at 0x10019a730
off = 0x10019a730 - text_base
print('=== ciphersuite_cb (full) ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x120], 0x10019a730)):
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
    else:
        print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 50:
        break
