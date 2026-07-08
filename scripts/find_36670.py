#!/usr/bin/env python3
"""Find what 0x100536670 is (called by do_rand_init_ossl_)."""
import lief
fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
syms = sorted([(s.value, s.name) for s in b.symbols if s.value], key=lambda x: x[0])
exact = [(v,n) for v,n in syms if v == 0x100536670]
if exact:
    print(f'0x100536670 = {exact[0][1]}')
else:
    print('No exact match')
