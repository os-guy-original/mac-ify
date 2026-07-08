#!/usr/bin/env python3
"""Check what function contains 0x1001a4e2e."""
import lief

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
syms = sorted([(s.value, s.name) for s in b.symbols if s.value], reverse=True)
for v, n in syms:
    if v <= 0x1001a4e2e:
        print(f'0x1001a4e2e is in {n} (0x{v:x}, +0x{0x1001a4e2e-v:x})')
        break
for v, n in syms:
    if v <= 0x1001a4ee9:
        print(f'0x1001a4ee9 is in {n} (0x{v:x}, +0x{0x1001a4ee9-v:x})')
        break
