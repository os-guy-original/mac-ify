#!/usr/bin/env python3
"""Find curl's ossl_ctx_setup or similar function that calls SSL_CTX_new_ex."""
import lief, capstone, struct

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]

# Search for all symbols containing 'ctx' and 'setup' or 'init' or 'new'
for sym in b.symbols:
    n = sym.name
    if n and ('ssl_ctx' in n.lower() or 'ossl_ctx' in n.lower() or 'ct_init' in n.lower() or 'ctx_setup' in n.lower() or 'ctx_new' in n.lower()):
        print(f'  0x{sym.value:x}: {n}')
