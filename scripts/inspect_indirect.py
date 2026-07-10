#!/usr/bin/env python3
"""Print indirect symbol table contents for a Mach-O binary."""

import struct
import sys

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 2
LC_DYSYMTAB = 0xb

def parse_macho(path):
    with open(path, 'rb') as f:
        data = f.read()
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack('<IiIIIIII', data[:32])
    off = 32
    cmds = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        cmds.append((cmd, cmdsize, off))
        off += cmdsize
    return data, cmds

def inspect(path, label):
    print(f'=== {label}: {path} ===')
    data, cmds = parse_macho(path)
    symtab_off = symtab_nsyms = strtab_off = strtab_size = 0
    indirectsym_off = nindirectsyms = 0
    for cmd, cmdsize, off in cmds:
        body = data[off:off+cmdsize]
        if cmd == LC_SYMTAB:
            symtab_off, symtab_nsyms, strtab_off, strtab_size = struct.unpack('<IIII', body[8:24])
        elif cmd == LC_DYSYMTAB:
            fields = struct.unpack('<18I', body[8:80])
            indirectsym_off = fields[12]
            nindirectsyms = fields[13]
    print(f'  symtab_off={symtab_off} nsyms={symtab_nsyms} strtab_off={strtab_off} strtab_size={strtab_size}')
    print(f'  indirectsym_off={indirectsym_off} nindirectsyms={nindirectsyms}')

    # Read symbol table
    syms = []
    for i in range(symtab_nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBHQ', data[symtab_off + i*16 : symtab_off + (i+1)*16])
        sym_name = data[strtab_off + n_strx:].split(b'\0', 1)[0].decode('utf-8', 'replace') if n_strx < strtab_size else ''
        syms.append((sym_name, n_type, n_sect, n_desc, n_value))

    # Read indirect sym table
    print(f'  --- Indirect symbol table ({nindirectsyms} entries) ---')
    INDIRECT_SYMBOL_LOCAL = 0x80000000
    INDIRECT_SYMBOL_ABS = 0x40000000
    for i in range(nindirectsyms):
        idx = struct.unpack('<I', data[indirectsym_off + i*4 : indirectsym_off + (i+1)*4])[0]
        if idx & INDIRECT_SYMBOL_LOCAL:
            print(f'    [{i}] LOCAL')
        elif idx & INDIRECT_SYMBOL_ABS:
            print(f'    [{i}] ABS')
        elif idx < symtab_nsyms:
            sym_name, n_type, n_sect, n_desc, n_value = syms[idx]
            print(f'    [{i}] sym[{idx}]={sym_name!r} type=0x{n_type:02x} sect={n_sect} value=0x{n_value:x}')
        else:
            print(f'    [{i}] OUT_OF_RANGE idx={idx}')

if __name__ == '__main__':
    inspect(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'binary')
