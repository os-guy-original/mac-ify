#!/usr/bin/env python3
import lief
fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
if b.has_dyld_info:
    di = b.dyld_info
    for bind in di.bindings:
        if bind.symbol and bind.symbol.name == '_malloc':
            print(f'  bind: {bind.symbol.name} at 0x{bind.address:x}')
