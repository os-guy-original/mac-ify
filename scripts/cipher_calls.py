#!/usr/bin/env python3
"""Find all call instructions in ssl_load_ciphers."""
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

# ssl_load_ciphers at 0x1005a6e40 — first ret at 0x1005a7061
# That's the success path (push 1; pop rax)
# Let me trace ALL calls in the first part (before first ret)
off = 0x1005a6e40 - text_base
insns = list(md.disasm(text_data[off:off+0x250], 0x1005a6e40))
for ins in insns:
    if ins.address >= 0x1005a7062:
        break
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
