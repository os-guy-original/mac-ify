#!/usr/bin/env python3
"""Disassemble CONF_parse_list to check how it calls the callback."""
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

# CONF_parse_list at 0x100290b10
# Signature: int CONF_parse_list(const char *list, char sep, int nosplit,
#                                void (*cb)(const char*, int, void*), void *arg)
# Args: rdi=list, rsi=sep, rdx=nosplit, rcx=cb, r8=arg
off = 0x100290b10 - text_base
print('=== CONF_parse_list ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x200], 0x100290b10)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 50:
        break
