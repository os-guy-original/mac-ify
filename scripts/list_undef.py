#!/usr/bin/env python3
import struct, sys

with open(sys.argv[1], 'rb') as f:
    data = f.read()
magic = struct.unpack('<I', data[:4])[0]
ncmds = struct.unpack('<I', data[16:20])[0]
off = 32
symtab_off = symtab_n = strtab_off = strtab_size = 0
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', data[off:off+8])
    if cmd == 2:
        symtab_off, symtab_n, strtab_off, strtab_size = struct.unpack('<IIII', data[off+8:off+24])
    off += cmdsize

undef_net = set()
for i in range(symtab_n):
    base = symtab_off + i * 16
    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBHQ', data[base:base+16])
    if (n_type & 0x1) and n_value == 0:
        name_end = data.index(b'\x00', strtab_off + n_strx)
        name = data[strtab_off + n_strx:name_end].decode('latin-1', 'replace')
        undef_net.add(name)

for s in sorted(undef_net):
    if any(k in s.lower() for k in ['send','recv','socket','connect','poll','select','read','write','close','fcntl','getaddr','gethost','getnameinfo','inet_','sockaddr','msg']):
        print(s)
