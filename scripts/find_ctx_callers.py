#!/usr/bin/env python3
"""Find all callers of SSL_CTX_new_ex (0x1001a4990) and SSL_CTX_new (0x1001a5020)."""
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

# Find calls to SSL_CTX_new (0x1001a5020) and SSL_CTX_new_ex (0x1001a4990)
for target, name in [(0x1001a5020, 'SSL_CTX_new'), (0x1001a4990, 'SSL_CTX_new_ex')]:
    print(f'\n=== Callers of {name} (0x{target:x}) ===')
    for ins in md.disasm(text_data, text_base):
        if ins.mnemonic == 'call':
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM and op.imm == target:
                    # Find enclosing function
                    for v, n in syms:
                        if v <= ins.address and v + 0x10000 > ins.address:
                            print(f'  0x{ins.address:x} in {n}')
                            break
                    break
