#!/usr/bin/env python3
"""Check which macOS symbols dust needs are missing from the macify shim."""
import subprocess
import re

# Get all exported symbols from the shim
result = subprocess.run(
    ['nm', '-D', '/home/z/my-project/mac-ify/build/libmacify_shim.so'],
    capture_output=True, text=True
)
def parse_nm(line):
    """Parse one nm line; return (type, symname) or None."""
    parts = line.split()
    if len(parts) >= 3 and parts[1] in ('T', 'D', 'B', 'R', 'W', 'C'):
        # symbol name may have @@version suffix
        return parts[1], parts[2].split('@')[0]
    if len(parts) == 2 and parts[0] in ('T', 'D', 'B', 'R', 'W', 'C'):
        return parts[0], parts[1].split('@')[0]
    return None

shim_syms = set()
for line in result.stdout.splitlines():
    p = parse_nm(line)
    if p:
        shim_syms.add(p[1])

# Also include symbols available from libc.so.6 / libm.so.6 / libresolv
def get_lib_syms(lib):
    r = subprocess.run(['nm', '-D', lib], capture_output=True, text=True)
    s = set()
    for line in r.stdout.splitlines():
        p = parse_nm(line)
        if p:
            s.add(p[1])
    return s

libc_syms = get_lib_syms('/lib/x86_64-linux-gnu/libc.so.6')
libm_syms = get_lib_syms('/lib/x86_64-linux-gnu/libm.so.6')
libresolv_syms = get_lib_syms('/lib/x86_64-linux-gnu/libresolv.so.2')
# Combine
all_known = shim_syms | libc_syms | libm_syms | libresolv_syms
print(f"Shim: {len(shim_syms)} syms, libc: {len(libc_syms)}, libm: {len(libm_syms)}")

# Parse dust binary's imports using lief
import lief
b = lief.parse('/home/z/my-project/mac-ify/tests/real/dust_macos')

imports = []
# Use bindings() iterator (newer lief API)
for bi in b.dyld_info.bindings:
    sym_name = bi.symbol.name if bi.symbol else '?'
    lib_name = bi.library.name if bi.library else '?'
    imports.append((sym_name, lib_name))

# Deduplicate
seen = set()
unique = []
for sym, lib in imports:
    key = (sym, lib)
    if key in seen: continue
    seen.add(key)
    unique.append((sym, lib))

# Strip leading underscore (macOS convention)
print(f"\nTotal unique imports: {len(unique)}")
print(f"\n=== Missing symbols (not in shim/libc/libm) ===\n")
missing = []
for sym, lib in sorted(unique):
    # Strip leading _ (macOS convention, macify does this at runtime)
    nm_sym = sym[1:] if sym.startswith('_') else sym
    # Strip $-suffix
    base = nm_sym.split('$')[0]
    if base in all_known or nm_sym in all_known or sym in all_known:
        continue
    missing.append((sym, lib))
    print(f"  {sym:40s} <- {lib}")

print(f"\nTotal missing: {len(missing)}")
