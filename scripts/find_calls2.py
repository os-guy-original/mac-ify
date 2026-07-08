#!/usr/bin/env python3
"""Find calls to SSL_CTX_new using capstone, scanning ALL instructions."""
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

# Find ALL call instructions that target 0x1001a4990 or 0x1001a5020
# Using a different approach: scan for E8 (call rel32) bytes
targets = {0x1001a4990: 'SSL_CTX_new_ex', 0x1001a5020: 'SSL_CTX_new'}

for ins in md.disasm(text_data, text_base):
    if ins.mnemonic == 'call':
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM and op.imm in targets:
                print(f'  call {targets[op.imm]} at 0x{ins.address:x}')
                break

# Also find JMP (tail calls)
for ins in md.disasm(text_data, text_base):
    if ins.mnemonic == 'jmp':
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM and op.imm in targets:
                print(f'  jmp {targets[op.imm]} at 0x{ins.address:x}')
                break
