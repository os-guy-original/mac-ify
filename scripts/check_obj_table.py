#!/usr/bin/env python3
"""Check what's at the OBJ_nid2obj table address."""
import lief, struct

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]

# OBJ_nid2obj at 0x100426420 uses:
# lea rdx, [rip + 0x325543]  at 0x100426436 -> next ins 0x10042643d
# target = 0x10042643d + 0x325543 = 0x10074b980
# This is the "so" table (struct so: {sn, ln, nid, ...})
# Each entry is 40 bytes (0x28): [0]=sn_ptr, [8]=ln_ptr, [16]=flag, [24]=?, [32]=?

table_addr = 0x10042643d + 0x325543
print(f'Table at 0x{table_addr:x}')

# Also: lea rcx, [rip + 0x325531] at 0x100426448 -> next ins 0x10042644f
# target = 0x10042644f + 0x325531 = 0x10074b980
# Same table!

# Read the table entries for nid 4 and nid 7
for sec in b.sections:
    if sec.virtual_address <= table_addr < sec.virtual_address + sec.size:
        off = table_addr - sec.virtual_address
        data = bytes(sec.content)
        # Each entry is 40 bytes. nid 4 = entry[4], nid 7 = entry[7]
        for nid in [1, 4, 7, 9]:
            entry_off = off + nid * 40
            sn_ptr = struct.unpack_from('<Q', data, entry_off)[0]
            ln_ptr = struct.unpack_from('<Q', data, entry_off + 8)[0]
            flag = struct.unpack_from('<I', data, entry_off + 16)[0]
            # Read sn string
            sn_str = '?'
            if sn_ptr > 0x100000000:
                for s2 in b.sections:
                    if s2.virtual_address <= sn_ptr < s2.virtual_address + s2.size:
                        sn_off = sn_ptr - s2.virtual_address
                        s2_data = bytes(s2.content)
                        end = s2_data.find(b'\x00', sn_off)
                        sn_str = s2_data[sn_off:end].decode('utf-8', errors='replace')
                        break
            print(f'  nid[{nid}]: sn=0x{sn_ptr:x} ({sn_str!r}) ln=0x{ln_ptr:x} flag={flag}')
        break

# Check: are the sn_ptr values rebased (have slide added)?
# In the file, they should be static addresses like 0x1005e7963
# If they're NOT rebased, they'll be 0x1005e7963 (file value)
# If they ARE rebased, they'll be 0x1005e7963 + slide
# But we're reading from the FILE, so they should be static values
print()
print('Note: these are file (static) values. At runtime, they should have slide added.')
