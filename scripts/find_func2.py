#!/usr/bin/env python3
"""Find what function contains 0x1000a6201."""
import lief

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
syms = sorted([(s.value, s.name) for s in b.symbols if s.value], reverse=True)
for v, n in syms:
    if v <= 0x1000a6201:
        print(f'0x1000a6201 is in {n} (0x{v:x}, +0x{0x1000a6201-v:x})')
        break
