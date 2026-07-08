#!/usr/bin/env python3
"""Find the RUN_ONCE init routine for RAND_get_rand_method.
The once_control is at [rip + 0x365233] from 0x100444436+7 = 0x10044443d
= 0x10044443d + 0x365233 = 0x1007a9670
The init_routine is at [rip - 0x1b4] from 0x10044443d+7 = 0x100444444
= 0x100444444 - 0x1b4 = 0x100444290 = do_rand_init_ossl_"""
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

# do_rand_init_ossl_ at 0x100444290
# Let's check what it does more carefully
off = 0x100444290 - text_base
print('=== do_rand_init_ossl_ ===')
for i, ins in enumerate(md.disasm(text_data[off:off+0x200], 0x100444290)):
    print(f'  0x{ins.address:x}: {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}')
    if 'ret' in ins.mnemonic and i > 0:
        break
    if i > 30:
        break
