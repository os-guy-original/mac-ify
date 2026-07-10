#!/usr/bin/env python3
"""Inspect LC_DYLD_CHAINED_FIXUPS format of a Mach-O binary."""

import struct
import sys

LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000028
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_DYLIB = 0xC

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

def inspect(path, label):
    print(f'=== {label}: {path} ===')
    data, cmds = parse_macho(path)
    cf_off = cf_size = None
    segments = []
    for cmd, cmdsize, off in cmds:
        name = {
            LC_SEGMENT_64: 'LC_SEGMENT_64',
            LC_DYLD_INFO: 'LC_DYLD_INFO',
            LC_DYLD_INFO_ONLY: 'LC_DYLD_INFO_ONLY',
            LC_DYLD_CHAINED_FIXUPS: 'LC_DYLD_CHAINED_FIXUPS',
        }.get(cmd, f'cmd=0x{cmd:08x}')
        body = data[off:off+cmdsize]
        if cmd == LC_SEGMENT_64:
            segname = body[8:24].rstrip(b'\0').decode('ascii', 'replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', body[24:56])
            maxprot, initprot, nsects, flags = struct.unpack('<iiII', body[56:72])
            print(f'  {name}: segname={segname!r} vmaddr=0x{vmaddr:x} vmsize=0x{vmsize:x} fileoff=0x{fileoff:x} filesize=0x{filesize:x} initprot=0x{initprot:x} nsects={nsects}')
            segments.append((segname, vmaddr, vmsize, initprot))
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            rebase_off, rebase_size, bind_off, bind_size, weak_off, weak_size, lazy_off, lazy_size, exp_off, exp_size = struct.unpack('<IIIIIIIIII', body[8:48])
            print(f'  {name}: rebase=(off={rebase_off},sz={rebase_size}) bind=(off={bind_off},sz={bind_size}) lazy=(off={lazy_off},sz={lazy_size}) export=(off={exp_off},sz={exp_size})')
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            dataoff, datasize = struct.unpack('<II', body[8:16])
            cf_off, cf_size = dataoff, datasize
            print(f'  {name}: dataoff={dataoff} datasize={datasize}')
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            name_off, timestamp, cur_ver, compat_ver = struct.unpack('<IIII', body[8:24])
            dylib_path = body[name_off:].split(b'\0', 1)[0].decode('utf-8', 'replace')
            print(f'  {name}: {dylib_path}')
        else:
            print(f'  {name}: size={cmdsize}')

    if cf_off is None:
        print('  No LC_DYLD_CHAINED_FIXUPS')
        return

    cf = data[cf_off:cf_off+cf_size]
    fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, symbols_format = struct.unpack('<IIIIII', cf[:24])
    print(f'  CF: version={fixups_version} starts_off={starts_offset} imports_off={imports_offset} symbols_off={symbols_offset} imports_count={imports_count} symbols_format={symbols_format}')

    # Parse starts_in_image: count + array of seg offsets
    sb = cf[starts_offset:]
    n_image_segs = struct.unpack('<I', sb[:4])[0]
    print(f'  starts_in_image: n_segs={n_image_segs}')
    seg_offs = struct.unpack(f'<{n_image_segs}I', sb[4:4+4*n_image_segs])
    print(f'    seg_offsets={seg_offs}')

    for i, soff in enumerate(seg_offs):
        if soff == 0:
            print(f'    seg {i} ({segments[i][0] if i < len(segments) else "?"}): no fixups')
            continue
        ss = sb[soff:]
        seg_size, page_size, ptr_format = struct.unpack('<IHH', ss[:8])
        seg_offset, = struct.unpack('<Q', ss[8:16])
        max_valid, page_count = struct.unpack('<IH', ss[16:22])
        page_starts = struct.unpack(f'<{page_count}H', ss[22:22+2*page_count])
        seg_name = segments[i][0] if i < len(segments) else '?'
        print(f'    seg {i} ({seg_name}): seg_size={seg_size} page_size={page_size} ptr_format={ptr_format} seg_offset=0x{seg_offset:x} max_valid=0x{max_valid:x} page_count={page_count}')
        print(f'      page_starts (first 10): {page_starts[:10]}')

    # Parse imports
    print(f'  --- imports ({imports_count} total) ---')
    for i in range(min(imports_count, 20)):
        imp_raw = struct.unpack('<I', cf[imports_offset + i*4 : imports_offset + (i+1)*4])[0]
        lib_ordinal = imp_raw & 0xFF
        weak = (imp_raw >> 8) & 1
        name_off = (imp_raw >> 9) & 0x7FFFFF
        # Read symbol name from symbols table
        sym_name = cf[symbols_offset + name_off:].split(b'\0', 1)[0].decode('utf-8', 'replace')
        print(f'    import {i}: lib_ordinal={lib_ordinal} weak={weak} sym={sym_name!r}')

    print()

if __name__ == '__main__':
    inspect(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'binary')
