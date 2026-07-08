#!/usr/bin/env python3
"""Find SSL_CTX_new_ex in curl's bindings."""
import lief

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]

if b.has_dyld_info:
    di = b.dyld_info
    for bind in di.bindings:
        if bind.symbol and 'SSL_CTX_new' in bind.symbol.name:
            print(f'  binding: {bind.symbol.name} at 0x{bind.address:x}')
