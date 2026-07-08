#!/usr/bin/env python3
"""Check missing symbols for any macOS binary."""
import subprocess
import sys
import lief

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <binary>")
    sys.exit(1)

binary = sys.argv[1]

# Get all exported symbols from the shim
def parse_nm(line):
    parts = line.split()
    if len(parts) >= 3 and parts[1] in ('T', 'D', 'B', 'R', 'W', 'C', 'i'):
        return parts[1], parts[2].split('@')[0]
    if len(parts) == 2 and parts[0] in ('T', 'D', 'B', 'R', 'W', 'C', 'i'):
        return parts[0], parts[1].split('@')[0]
    return None

result = subprocess.run(['nm', '-D', '/home/z/my-project/mac-ify/build/libmacify_shim.so'], capture_output=True, text=True)
shim_syms = set()
for line in result.stdout.splitlines():
    p = parse_nm(line)
    if p: shim_syms.add(p[1])

def get_lib_syms(lib):
    r = subprocess.run(['nm', '-D', lib], capture_output=True, text=True)
    s = set()
    for line in r.stdout.splitlines():
        p = parse_nm(line)
        if p: s.add(p[1])
    return s

libc_syms = get_lib_syms('/lib/x86_64-linux-gnu/libc.so.6')
libm_syms = get_lib_syms('/lib/x86_64-linux-gnu/libm.so.6')
all_known = shim_syms | libc_syms | libm_syms

b = lief.parse(binary)
seen = set()
unique = []
for bi in b.dyld_info.bindings:
    sym = bi.symbol.name if bi.symbol else '?'
    lib = bi.library.name if bi.library else '?'
    if (sym, lib) not in seen:
        seen.add((sym, lib))
        unique.append((sym, lib))

print(f"Total unique imports: {len(unique)}")
print(f"\n=== Missing symbols ===\n")
missing = []
for sym, lib in sorted(unique):
    nm_sym = sym[1:] if sym.startswith('_') else sym
    base = nm_sym.split('$')[0]
    if base in all_known or nm_sym in all_known or sym in all_known:
        continue
    missing.append((sym, lib))
    print(f"  {sym:45s} <- {lib}")

print(f"\nTotal missing: {len(missing)}")
