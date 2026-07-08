#!/usr/bin/env python3
"""Find the 'could not create a context' string in any section."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

target_str = b'could not create a context'
idx = 0
while True:
    idx = data.find(target_str, idx)
    if idx == -1:
        break
    print(f'  String at file 0x{idx:x} (static 0x{0x100000000+idx:x})')
    idx += 1
