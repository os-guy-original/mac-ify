#!/usr/bin/env python3
import lief, struct

fat = lief.MachO.parse('/home/z/my-project/mac-ify/tests/real/curl_macos')
b = fat[0]
for sec in b.sections:
    if sec.name == '__stubs':
        if sec.virtual_address <= 0x1005baeac < sec.virtual_address + sec.size:
            print(f'0x1005baeac is in __stubs')
            with open('/home/z/my-project/mac-ify/tests/real/curl_macos', 'rb') as f:
                data = f.read()
            ncmds = struct.unpack_from('<I', data, 16)[0]
            off2 = 32
            symtab_off = symtab_nsyms = strtab_off = 0
            indirectsym_off = 0
            for _ in range(ncmds):
                cmd, cmdsize = struct.unpack_from('<II', data, off2)
                if cmd == 2:
                    symoff, nsyms, stroff, _ = struct.unpack_from('<IIII', data, off2 + 8)
                    symtab_off, symtab_nsyms, strtab_off = symoff, nsyms, stroff
                elif cmd == 0xb:
                    fields = struct.unpack_from('<18I', data, off2 + 8)
                    indirectsym_off = fields[12]
                off2 += cmdsize
            stub_idx = (0x1005baeac - sec.virtual_address) // 6
            print(f'  stub_idx = {stub_idx}')
            indices = struct.unpack_from(f'<{sec.size//6}I', data, indirectsym_off + sec.reserved1*4)
            sym_idx = indices[stub_idx]
            sym_off = symtab_off + sym_idx * 16
            n_strx = struct.unpack_from('<I', data, sym_off)[0]
            end = data.find(b'\x00', strtab_off + n_strx)
            name = data[strtab_off + n_strx:end].decode()
            print(f'  stub[{stub_idx}] = {name}')
        break
