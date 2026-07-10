#!/usr/bin/env python3
"""Inspect all sections and find GOT/la_symbol_ptr entries."""

import struct
import sys

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 2
LC_DYSYMTAB = 0xb

def parse_macho(path):
    with open(path, 'rb') as f:
        data = f.read()
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack('<IiIIIIII', data[:32])
    print(f'  filetype={filetype} (6=DYLIB, 2=EXEC) ncmds={ncmds}')
    off = 32
    cmds = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        cmds.append((cmd, cmdsize, off))
        off += cmdsize
    return data, cmds

def inspect_sections(path, label):
    print(f'=== {label}: {path} ===')
    data, cmds = parse_macho(path)

    symtab_off = symtab_nsyms = strtab_off = strtab_size = 0
    indirectsym_off = 0

    for cmd, cmdsize, off in cmds:
        body = data[off:off+cmdsize]
        if cmd == LC_SEGMENT_64:
            segname = body[8:24].rstrip(b'\0').decode('ascii', 'replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', body[24:56])
            maxprot, initprot, nsects, flags = struct.unpack('<iiII', body[56:72])
            print(f'  {segname}: vmaddr=0x{vmaddr:x} vmsize=0x{vmsize:x} initprot=0x{initprot:x} nsects={nsects}')
            sect_off = off + 72
            for j in range(nsects):
                sect_data = data[sect_off:sect_off+80]
                sectname = sect_data[:16].rstrip(b'\0').decode('ascii', 'replace')
                s_segname = sect_data[16:32].rstrip(b'\0').decode('ascii', 'replace')
                addr, size, offset, align, reloff, nreloc, s_flags, s_reserved1, s_reserved2, s_reserved3 = struct.unpack('<QQIIIIIIII', sect_data[32:80])
                print(f'    {s_segname}.{sectname}: addr=0x{addr:x} size=0x{size:x} offset=0x{offset:x} flags=0x{s_flags:x} r1={s_reserved1} r2={s_reserved2}')
                sect_off += 80
        elif cmd == LC_SYMTAB:
            symtab_off, symtab_nsyms, strtab_off, strtab_size = struct.unpack('<IIII', body[8:24])
            print(f'  LC_SYMTAB: symoff={symtab_off} nsyms={symtab_nsyms} stroff={strtab_off} strsize={strtab_size}')
        elif cmd == LC_DYSYMTAB:
            ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym, tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms, indirectsym_off, nindirectsyms, extreloff, nextrel, locreloff, nlocrel = struct.unpack('<18I', body[8:80])
            print(f'  LC_DYSYMTAB: indirectsym_off={indirectsym_off} nindirectsyms={nindirectsyms}')
            print(f'    iextdefsym={iextdefsym} nextdefsym={nextdefsym} iundefsym={iundefsym} nundefsym={nundefsym}')

    # Look at indirect symbol table
    if indirectsym_off and symtab_off and strtab_off:
        print(f'  --- Indirect symbols ---')
        syms = []
        for i in range(symtab_nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBHQ', data[symtab_off + i*16 : symtab_off + (i+1)*16])
            sym_name = data[strtab_off + n_strx:].split(b'\0', 1)[0].decode('utf-8', 'replace') if n_strx < strtab_size else ''
            syms.append((sym_name, n_type, n_value))

        # Print first 30 indirect symbols
        for i in range(min(40, struct.unpack('<I', data[cmds[0][2]+8:cmds[0][2]+12])[0])):  # placeholder
            pass

    print()

if __name__ == '__main__':
    inspect_sections(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'binary')
