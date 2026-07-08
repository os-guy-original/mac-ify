#!/usr/bin/env python3
"""Find all references to the string 'SSL_CTX_new_ex' and 'SSL_CTX_new'."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

# Find the string "SSL_CTX_new_ex\x0" (without leading underscore)
for s in [b'SSL_CTX_new_ex\x00', b'SSL_CTX_new\x00', b'_SSL_CTX_new_ex\x00', b'_SSL_CTX_new\x00']:
    idx = 0
    while True:
        idx = data.find(s, idx)
        if idx == -1:
            break
        print(f'  String {s!r} at file 0x{idx:x} (static 0x{0x100000000+idx:x})')
        idx += 1

# Also check: does curl use dlopen/dlsym for SSL?
# Search for "SSL_CTX_new" as a dlsym lookup string (null-terminated)
# These would be in __TEXT.__cstring or __DATA
