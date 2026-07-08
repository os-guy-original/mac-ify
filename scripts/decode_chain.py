#!/usr/bin/env python3
"""Decode chained fixup entries from sqlite3 __DATA segment."""

import struct

FILE = "/home/z/my-project/mac-ify/tests/real/sqlite3_macos"
with open(FILE, 'rb') as f:
    data = f.read()

# __DATA segment: file offset 0x152000, size 0x6000 (vmsize) / 0x5000 (filesize)
# Page 0: file offset 0x152000 to 0x153000
PAGE0_FILE_OFF = 0x152000
PAGE0_STATIC = 0x100152000
PAGE0_SIZE = 0x1000

# Decode DYLD_CHAINED_PTR_64_OFFSET format
def decode_rebase(value):
    target = value & ((1<<43) - 1)
    high8 = (value >> 43) & 0xFF
    nxt = (value >> 51) & 0xFFF
    bind = (value >> 63) & 1
    return (bind, nxt, high8, target)

def decode_bind(value):
    ordinal = value & 0xFFFF
    addend = (value >> 16) & 0xFFFF
    nxt = (value >> 51) & 0xFFF
    bind = (value >> 63) & 1
    return (bind, nxt, ordinal, addend)

# Walk page 0 chain starting at offset 0
print(f"=== __DATA page 0 (static 0x{PAGE0_STATIC:x}) ===")
print(f"page_start = 0 (chain starts at offset 0)")
chain_off = 0
iters = 0
seen = []
while iters < 1000:
    file_off = PAGE0_FILE_OFF + chain_off
    if file_off + 8 > len(data):
        print(f"  chain past file end at +0x{chain_off:03x}")
        break
    val = struct.unpack_from('<Q', data, file_off)[0]
    static_addr = PAGE0_STATIC + chain_off
    bind = (val >> 63) & 1
    nxt = (val >> 51) & 0xFFF
    if bind:
        ordinal = val & 0xFFFF
        addend = (val >> 16) & 0xFFFF
        # only print first/last and around target
        if iters < 5 or chain_off >= 0x6e0:
            print(f"  +0x{chain_off:03x} (static 0x{static_addr:x}): BIND val=0x{val:016x} ordinal={ordinal} addend={addend} next=0x{nxt:x} (next_off=0x{nxt*4:x})")
        seen.append((chain_off, 'bind', ordinal))
    else:
        target = val & ((1<<43) - 1)
        high8 = (val >> 43) & 0xFF
        if iters < 5 or chain_off >= 0x6e0:
            print(f"  +0x{chain_off:03x} (static 0x{static_addr:x}): REBASE val=0x{val:016x} target=0x{target:x} high8=0x{high8:x} next=0x{nxt:x} (next_off=0x{nxt*4:x})")
        seen.append((chain_off, 'rebase', target))
    if nxt == 0:
        print(f"  chain ends at +0x{chain_off:03x}")
        break
    chain_off += nxt * 4
    if chain_off + 8 > PAGE0_SIZE:
        print(f"  chain past page end at +0x{chain_off:03x}")
        break
    iters += 1

print(f"\nTotal fixups seen: {len(seen)}")
print(f"First few: {seen[:3]}")
print(f"Last few: {seen[-3:]}")
print(f"Fixup at +0x6f8 reached: {0x6f8 in [s[0] for s in seen]}")

# Did we walk PAST 0x6f8?
past_6f8 = [s for s in seen if s[0] > 0x6f8]
if past_6f8:
    print(f"Chain walked past 0x6f8: yes (entries {len(past_6f8)} past)")
    # Show entries around 0x6f8
    near = [s for s in seen if 0x6c0 <= s[0] <= 0x720]
    print(f"Entries near 0x6f8: {near}")
    # Find the gap
    before_6f8 = [s for s in seen if s[0] < 0x6f8]
    after_6f8 = [s for s in seen if s[0] > 0x6f8]
    if before_6f8 and after_6f8:
        last_before = before_6f8[-1]
        first_after = after_6f8[0]
        print(f"Last entry BEFORE 0x6f8: +0x{last_before[0]:03x} {last_before}")
        print(f"First entry AFTER 0x6f8: +0x{first_after[0]:03x} {first_after}")
        # Check what value is at last_before + (some offset)
        # The next pointer of last_before determines where the chain goes
        # Read raw value at last_before
        val_at_last = struct.unpack_from('<Q', data, 0x152000 + last_before[0])[0]
        nxt = (val_at_last >> 51) & 0xFFF
        next_off = last_before[0] + nxt * 4
        print(f"  -> next pointer = 0x{nxt:x} (offset 0x{nxt*4:x}) -> next entry at +0x{next_off:03x}")
        print(f"  -> skipped range: 0x{last_before[0]+8:03x} to 0x{next_off-1:03x}")
else:
    print(f"Chain walked past 0x6f8: no")
    # Find where chain ends
    if seen:
        print(f"Last entry: +0x{seen[-1][0]:03x}")

# Also try to find ANY value at offset 0x6f8 in the raw data
print(f"\n=== Raw value at offset 0x6f8 (static 0x1001526f8) ===")
val_at_6f8 = struct.unpack_from('<Q', data, 0x152000 + 0x6f8)[0]
print(f"  raw value: 0x{val_at_6f8:016x}")
bind, nxt, high8, target = decode_rebase(val_at_6f8)
print(f"  decoded: bind={bind} next=0x{nxt:x} high8=0x{high8:x} target=0x{target:x}")
