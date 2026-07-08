#!/usr/bin/env python3
"""Find all LEA rip+disp32 in __TEXT that target addresses near the error strings.
Maybe the string address calculation is slightly different."""
import struct

with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
    data = f.read()

# The error string "could not create a context" is at 0x1005d15c5
# But maybe curl uses a FORMAT string like "SSL: could not create a context: %s"
# which includes the prefix
# Let me search for the full format string
target_str = b'SSL: could not create a context'
idx = 0
while True:
    idx = data.find(target_str, idx)
    if idx == -1:
        break
    # Read the full string until null
    end = data.find(b'\x00', idx)
    full = data[idx:end].decode('utf-8', errors='replace')
    print(f'  Full string at file 0x{idx:x} (static 0x{0x100000000+idx:x}): {full!r}')
    idx += 1

# Also search for just "could not create a context" with context
target_str = b'could not create a context'
idx = 0
while True:
    idx = data.find(target_str, idx)
    if idx == -1:
        break
    # Read surrounding context
    start = max(0, idx - 20)
    end = data.find(b'\x00', idx)
    full = data[start:end].decode('utf-8', errors='replace')
    print(f'  Context at file 0x{idx:x}: ...{full!r}...')
    idx += 1
