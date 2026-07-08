#!/usr/bin/env python3
import lief
fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
for sym in b.symbols:
    n = sym.name
    if n and ('OBJ_nid2sn' in n or 'OBJ_obj2nid' in n or 'OBJ_sn2nid' in n or 'OBJ_create' in n or 'obj_add' in n or 'OBJ_NAME_add' in n or 'OBJ_bsearch' in n):
        print(f'  0x{sym.value:x}: {n}')
