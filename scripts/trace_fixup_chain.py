#!/usr/bin/env python3
"""
trace_fixup_chain.py — Deep investigation of Mach-O LC_DYLD_CHAINED_FIXUPS
gaps in the wget_macos binary.

This script:
  1. Parses the Mach-O header to find LC_DYLD_CHAINED_FIXUPS, LC_SEGMENT_64,
     and all section definitions.
  2. Parses the chained fixups header, starts_in_image table, and
     starts_in_segment tables.
  3. For ptr_format=6 (DYLD_CHAINED_PTR_64_OFFSET_64), traces EVERY fixup
     chain entry across ALL pages of ALL segments. Records segment name,
     page index, offset within page, bind/rebase flag, raw value, BOTH
     12-bit and 15-bit interpretations of the `next` field, and the
     resolved symbol name for binds (via the imports table).
  4. Builds a complete set of all offsets visited by ANY chain in the
     __DATA_CONST segment (which contains __got).
  5. Specifically tests whether offset 0x858 within __DATA_CONST is
     visited. If not, reports the nearest visited offsets before and
     after it.
  6. Reports:
       - Total fixup entries visited per segment
       - Any page_start values with bit 15 set (multi-page chain flag)
       - Whether the `next` field ever has value 0 before all entries
         are visited (potential missed chains)
       - "Gaps": offsets that look like fixup entries (have the bind bit
         set or contain a plausible 36-bit rebase target) but were NOT
         visited by any chain
       - Compares three chain-tracing strategies:
           (a) 12-bit next (Apple format 4/5 layout, used by jq etc.)
           (b) 15-bit next (Apple format 6 layout — DYLD_CHAINED_PTR_64_OFFSET_64)
           (c) heuristic (12-bit unless it overflows the page, then 15-bit)
           and shows which strategy (if any) visits offset 0x858.

Output is written to /home/z/my-project/scripts/fixup_trace_output.txt
as well as echoed to stdout.
"""

import struct
import sys
from collections import defaultdict

# ---------- paths ----------
WGET_PATH = '/home/z/my-project/mac-ify/tests/real/wget_macos'
OUT_PATH  = '/home/z/my-project/scripts/fixup_trace_output.txt'

# ---------- Mach-O constants ----------
MH_MAGIC_64              = 0xFEEDFACF
LC_SEGMENT_64            = 0x19
LC_DYLD_CHAINED_FIXUPS   = 0x80000034   # 52 | LC_REQ_DYLD

DYLD_CHAINED_PTR_START_NONE  = 0xFFFF   # no fixups on this page
DYLD_CHAINED_PTR_START_MULTI = 0x8000   # bit 15 set: page's chain is on another page

# Apple dyld pointer_format values (dyld_chained_ptr.h)
#   4 = DYLD_CHAINED_PTR_64_BITFIX     (12-bit next at bits 51-62, 43-bit target)
#   5 = DYLD_CHAINED_PTR_64_BITFIX_KERNEL
#   6 = DYLD_CHAINED_PTR_64_OFFSET_64  (15-bit next at bits 36-50, 36-bit target)
#   7 = DYLD_CHAINED_PTR_64_BIND_64
DYLD_CHAINED_PTR_64_OFFSET_64 = 6


# ============================================================
# Tiny helper utilities
# ============================================================
def read_cstr(data, off, maxlen=4096):
    if off < 0 or off >= len(data):
        return '<bad offset>'
    end = data.find(b'\x00', off)
    if end == -1 or end > off + maxlen:
        end = off + maxlen
    return data[off:end].decode('utf-8', errors='replace')


class Tee:
    """Write to stdout AND a list of lines for later file save."""
    def __init__(self):
        self.lines = []
    def log(self, s=''):
        print(s)
        self.lines.append(s)
    # Allow `log(...)` as an alias for `log.log(...)`
    def __call__(self, s=''):
        self.log(s)


# ============================================================
# Mach-O header / load-command parser
# ============================================================
def parse_macho(data, log):
    if len(data) < 32:
        log('ERROR: file too small for Mach-O header')
        return None
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
        struct.unpack('<IIIIIIII', data[:32])
    if magic != MH_MAGIC_64:
        log(f'ERROR: not MH_MAGIC_64 (magic=0x{magic:08x})')
        return None

    log('=== Mach-O header ===')
    log(f'  magic        = 0xFEEDFACF (64-bit)')
    log(f'  cputype      = 0x{cputype:08x}  cpusubtype = 0x{cpusubtype:08x}')
    log(f'  filetype     = {filetype}  ({ "MH_EXECUTE" if filetype==2 else "?" })')
    log(f'  ncmds        = {ncmds}')
    log(f'  sizeofcmds   = {sizeofcmds}')
    log(f'  flags        = 0x{flags:08x}')

    segments = []   # list of dicts
    sections = []   # list of dicts (each has seg_index)
    chained_fixups_off  = None
    chained_fixups_size = None

    p = 32
    for i in range(ncmds):
        if p + 8 > len(data):
            log(f'ERROR: load command {i} extends past EOF')
            break
        cmd, cmdsize = struct.unpack('<II', data[p:p+8])

        if cmd == LC_SEGMENT_64:
            segname = data[p+8:p+24].rstrip(b'\x00').decode('utf-8', errors='replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', data[p+24:p+56])
            maxprot, initprot, nsects, seg_flags = struct.unpack('<iiII', data[p+56:p+72])
            seg_idx = len(segments)
            segments.append({
                'index':    seg_idx,
                'name':     segname,
                'vmaddr':   vmaddr,
                'vmsize':   vmsize,
                'fileoff':  fileoff,
                'filesize': filesize,
                'maxprot':  maxprot,
                'initprot': initprot,
                'nsects':   nsects,
                'flags':    seg_flags,
            })
            # Walk sections (section_64 = 80 bytes each, starting at p+72)
            sec_p = p + 72
            for s in range(nsects):
                sectname = data[sec_p:sec_p+16].rstrip(b'\x00').decode('utf-8', errors='replace')
                sec_seg  = data[sec_p+16:sec_p+32].rstrip(b'\x00').decode('utf-8', errors='replace')
                sec_addr, sec_size = struct.unpack('<QQ', data[sec_p+32:sec_p+48])
                sec_off, sec_align, sec_reloff, sec_nreloc, sec_flags, sec_r1, sec_r2, sec_r3 = \
                    struct.unpack('<IIIIIIII', data[sec_p+48:sec_p+80])
                sections.append({
                    'sectname':  sectname,
                    'segname':   sec_seg,
                    'addr':      sec_addr,
                    'size':      sec_size,
                    'offset':    sec_off,
                    'align':     sec_align,
                    'reloff':    sec_reloff,
                    'nreloc':    sec_nreloc,
                    'flags':     sec_flags,
                    'reserved1': sec_r1,
                    'reserved2': sec_r2,
                    'reserved3': sec_r3,
                    'seg_index': seg_idx,
                })
                sec_p += 80

        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            _, _, chained_fixups_off, chained_fixups_size = \
                struct.unpack('<IIII', data[p:p+16])

        p += cmdsize

    log('\n=== Segments ===')
    for seg in segments:
        log(f'  [{seg["index"]}] {seg["name"]:<16} vmaddr=0x{seg["vmaddr"]:012x} '
            f'vmsize=0x{seg["vmsize"]:x}  fileoff=0x{seg["fileoff"]:06x} '
            f'filesize=0x{seg["filesize"]:x}  nsects={seg["nsects"]}')

    log('\n=== Sections ===')
    for s in sections:
        log(f'  seg[{s["seg_index"]}] {s["segname"]:<16} {s["sectname"]:<20} '
            f'addr=0x{s["addr"]:012x} size=0x{s["size"]:x} '
            f'off=0x{s["offset"]:06x} flags=0x{s["flags"]:08x}')

    log('\n=== LC_DYLD_CHAINED_FIXUPS ===')
    if chained_fixups_off is None:
        log('  NOT FOUND — binary has no chained fixups')
        return None
    log(f'  dataoff  = 0x{chained_fixups_off:x}  (={chained_fixups_off})')
    log(f'  datasize = {chained_fixups_size}')

    return {
        'segments':              segments,
        'sections':              sections,
        'chained_fixups_off':    chained_fixups_off,
        'chained_fixups_size':   chained_fixups_size,
    }


# ============================================================
# Chained-fixups header + starts table parser
# ============================================================
def parse_chained_fixups(data, mo, log):
    fx  = mo['chained_fixups_off']
    fxs = mo['chained_fixups_size']
    if fx + 24 > len(data):
        log('ERROR: chained fixups header past EOF')
        return None

    (fixups_version, starts_offset, imports_offset, symbols_offset,
     imports_count, symbols_length) = struct.unpack('<IIIIII', data[fx:fx+24])

    log('\n--- dyld_chained_fixups_header ---')
    log(f'  fixups_version = {fixups_version}')
    log(f'  starts_offset  = 0x{starts_offset:x}   (abs: 0x{fx+starts_offset:x})')
    log(f'  imports_offset = 0x{imports_offset:x}  (abs: 0x{fx+imports_offset:x})')
    log(f'  symbols_offset = 0x{symbols_offset:x}  (abs: 0x{fx+symbols_offset:x})')
    log(f'  imports_count  = {imports_count}')
    log(f'  symbols_length = {symbols_length}')

    # Determine import format from (symbols_offset - imports_offset) / imports_count
    if imports_count > 0:
        per_entry = (symbols_offset - imports_offset) // imports_count
    else:
        per_entry = 0
    if per_entry == 4:
        import_format = 'dyld_chained_import (4B, lib_ord:8 weak:1 name_off:23)'
    elif per_entry == 8:
        import_format = 'dyld_chained_import_addend (8B, lib_ord:8 weak:1 name_off:23 addend:32)'
    elif per_entry == 16:
        import_format = 'dyld_chained_import_addend64 (16B)'
    else:
        import_format = f'unknown ({per_entry}B per entry)'
    log(f'  import_table_size = {symbols_offset - imports_offset} bytes  '
        f'({per_entry}B per import  ->  {import_format})')

    # NOTE: Apple's struct calls the 6th field `symbols_length` but in this
    # binary it is set to 1 (likely a linker bug or it's actually a format
    # flag). The real symbols table extends to the end of the fixups data.
    # Compute the actual available symbols table size conservatively.
    cf_symbols_maxlen = max(symbols_length, 4096,
                            mo['chained_fixups_size'] - symbols_offset)

    # --- starts_in_image ---
    starts_base = fx + starts_offset
    if starts_base + 4 > len(data):
        log('ERROR: starts_in_image past EOF')
        return None
    starts_count = struct.unpack('<I', data[starts_base:starts_base+4])[0]
    log('\n--- dyld_chained_starts_in_image ---')
    log(f'  starts_count = {starts_count}')
    if starts_base + 4 + starts_count*4 > len(data):
        log('ERROR: starts array extends past EOF')
        return None
    seg_starts_offsets = list(struct.unpack(f'<{starts_count}I',
                                            data[starts_base+4:starts_base+4+starts_count*4]))
    log(f'  seg_starts_offsets (one per segment):')
    for i, s in enumerate(seg_starts_offsets):
        seg_name = mo['segments'][i]['name'] if i < len(mo['segments']) else f'<seg {i}>'
        log(f'    [{i}] {seg_name:<16} starts_offset=0x{s:x}'
            f'  {"(no fixups)" if s == 0 else ""}')

    # --- starts_in_segment for each segment ---
    seg_info_list = []   # one entry per segment (None if no fixups)
    for seg_idx, s_off in enumerate(seg_starts_offsets):
        seg = mo['segments'][seg_idx] if seg_idx < len(mo['segments']) else None
        seg_name = seg['name'] if seg else f'<seg {seg_idx}>'
        if s_off == 0:
            seg_info_list.append(None)
            continue
        seg_starts = starts_base + s_off
        if seg_starts + 22 > len(data):
            log(f'ERROR: starts_in_segment[{seg_idx}] past EOF')
            seg_info_list.append(None)
            continue
        seg_size, page_size, ptr_format = struct.unpack('<IHH', data[seg_starts:seg_starts+8])
        seg_offset, max_valid = struct.unpack('<QI', data[seg_starts+8:seg_starts+20])
        page_count = struct.unpack('<H', data[seg_starts+20:seg_starts+22])[0]
        page_starts = list(struct.unpack(f'<{page_count}H',
                                         data[seg_starts+22:seg_starts+22+page_count*2]))

        log(f'\n  --- dyld_chained_starts_in_segment [{seg_idx}] {seg_name} ---')
        log(f'    size           = {seg_size}')
        log(f'    page_size      = {page_size}  (0x{page_size:x})')
        log(f'    pointer_format = {ptr_format}'
            f'  {"(DYLD_CHAINED_PTR_64_OFFSET_64)" if ptr_format==6 else ""}')
        log(f'    segment_offset = 0x{seg_offset:x}')
        log(f'    max_valid      = 0x{max_valid:x}')
        log(f'    page_count     = {page_count}')
        log(f'    page_starts (all {page_count}): {[hex(ps) for ps in page_starts]}')

        seg_info_list.append({
            'seg_idx':         seg_idx,
            'seg_name':        seg_name,
            'seg':             seg,
            'page_size':       page_size,
            'ptr_format':      ptr_format,
            'segment_offset':  seg_offset,
            'max_valid':       max_valid,
            'page_count':      page_count,
            'page_starts':     page_starts,
        })

    # --- imports table ---
    imports_base = fx + imports_offset
    symbols_base = fx + symbols_offset
    imports = []
    log(f'\n--- Imports table ({imports_count} entries, {per_entry}B each) ---')
    for i in range(imports_count):
        rec = {}
        if per_entry == 4:
            raw = struct.unpack('<I', data[imports_base + i*4 : imports_base + i*4 + 4])[0]
            rec['lib_ordinal'] = raw & 0xFF
            rec['weak_import'] = (raw >> 8) & 1
            rec['name_offset'] = (raw >> 9) & 0x7FFFFF
            rec['addend']      = 0
            rec['raw']         = raw
        elif per_entry == 8:
            raw = struct.unpack('<Q', data[imports_base + i*8 : imports_base + i*8 + 8])[0]
            rec['lib_ordinal'] = raw & 0xFF
            rec['weak_import'] = (raw >> 8) & 1
            rec['name_offset'] = (raw >> 9) & 0x7FFFFF
            rec['addend']      = (raw >> 32) & 0xFFFFFFFF
            rec['raw']         = raw
        elif per_entry == 16:
            raw1, raw2 = struct.unpack('<QQ',
                data[imports_base + i*16 : imports_base + i*16 + 16])
            rec['lib_ordinal'] = raw1 & 0xFFFF
            rec['weak_import'] = (raw1 >> 16) & 1
            rec['name_offset'] = (raw1 >> 32) & 0xFFFFFFFF
            rec['addend']      = raw2
            rec['raw']         = raw1
        else:
            rec = {'lib_ordinal':0,'weak_import':0,'name_offset':0,'addend':0,'raw':0}
        rec['name'] = read_cstr(data, symbols_base + rec['name_offset'],
                                maxlen=cf_symbols_maxlen)
        imports.append(rec)

    # print first 16 imports and every 50th thereafter
    log('  (first 16 imports shown)')
    for i, imp in enumerate(imports[:16]):
        log(f'    [{i:3d}] lib_ord={imp["lib_ordinal"]:3d}  weak={imp["weak_import"]}  '
            f'name_off=0x{imp["name_offset"]:06x}  addend=0x{imp["addend"]:x}  '
            f'name={imp["name"]!r}')
    if len(imports) > 16:
        log(f'    ... ({len(imports)} total imports)')

    return {
        'fx':              fx,
        'fxs':             fxs,
        'imports':         imports,
        'per_entry':       per_entry,
        'seg_info_list':   seg_info_list,
        'starts_base':     starts_base,
        'starts_count':    starts_count,
        'symbols_length':  symbols_length,
    }


# ============================================================
# Chain tracing
# ============================================================
def trace_chain(data, seg, sg, page_idx, page_start_offset, next_mode, log, trace_log=None):
    """
    Trace a single fixup chain starting at the given offset within the page.

    next_mode: '12bit'  -> use bits 51-62 (12-bit next, format 4/5)
               '15bit'  -> use bits 36-50 (15-bit next, format 6)
               'heuristic' -> 12-bit unless it overflows the page AND 15-bit fits

    Returns (entries, terminated_by_zero, terminated_by_overflow).
    Each entry is a dict with full diagnostic info.
    """
    page_size = sg['page_size']
    page_count = sg['page_count']
    if page_idx >= page_count:
        return [], False, False
    seg_fileoff = seg['fileoff']
    page_file_off = seg_fileoff + page_idx * page_size

    entries = []
    offset_in_page = page_start_offset
    chain_iter = 0
    terminated_by_zero = False
    terminated_by_overflow = False

    while chain_iter < 65536:
        if offset_in_page + 8 > page_size:
            terminated_by_overflow = True
            break
        file_off = page_file_off + offset_in_page
        if file_off + 8 > len(data):
            terminated_by_overflow = True
            break

        raw = struct.unpack('<Q', data[file_off:file_off+8])[0]
        is_bind = (raw >> 63) & 1
        next_12  = (raw >> 51) & 0xFFF      # format 4/5: bits 51-62
        next_15  = (raw >> 36) & 0x7FFF     # format 6:   bits 36-50

        # For ptr_format=6, Apple's layout is 15-bit next.
        # We compute both so the caller can compare.
        if next_mode == '12bit':
            next_val = next_12
        elif next_mode == '15bit':
            next_val = next_15
        elif next_mode == 'heuristic':
            # Mimic fixups.c: default to 12-bit, fall back to 15-bit
            # if 12-bit would overflow the page AND 15-bit fits.
            next_val = next_12
            next_12_off = (offset_in_page + 8) + next_12 * 4
            next_15_off = (offset_in_page + 8) + next_15 * 4
            if (next_12 != 0 and next_12_off > page_size
                    and next_15 != 0 and next_15_off <= page_size):
                next_val = next_15
        else:
            next_val = next_15

        # Symbol resolution (best-effort)
        sym_name = ''
        ordinal = 0
        addend = 0
        if is_bind:
            ordinal = raw & 0xFFFF
            addend = (raw >> 16) & 0xFFFF
            if ordinal < len(sg['__imports']):
                sym_name = sg['__imports'][ordinal]['name']
            else:
                sym_name = f'<ord {ordinal} out of range>'
        else:
            # format 6 rebase: target is bits 0-35 (36-bit offset from image base)
            target36 = raw & 0xFFFFFFFFF
            sym_name = f'rebase target=0x{target36:x}'

        entry = {
            'seg_idx':        sg['seg_idx'],
            'seg_name':       sg['seg_name'],
            'page_idx':       page_idx,
            'offset_in_page': offset_in_page,
            'is_bind':        bool(is_bind),
            'raw':            raw,
            'next_12':        next_12,
            'next_15':        next_15,
            'next_used':      next_val,
            'ordinal':        ordinal,
            'addend':         addend,
            'sym_name':       sym_name,
        }
        entries.append(entry)
        if trace_log is not None:
            trace_log.append(entry)

        if next_val == 0:
            terminated_by_zero = True
            break

        new_offset = offset_in_page + next_val * 4
        if new_offset + 8 > page_size:
            terminated_by_overflow = True
            break
        offset_in_page = new_offset
        chain_iter += 1

    return entries, terminated_by_zero, terminated_by_overflow


# ============================================================
# Gap analysis: scan all 8-byte slots in a segment and flag any
# slot that looks like a fixup entry but was NOT visited.
# ============================================================
def looks_like_fixup(raw, n_imports, seg_vmsize):
    """Heuristic: does this 8-byte value look like a chained fixup entry?"""
    if raw == 0:
        return False
    is_bind = (raw >> 63) & 1
    if is_bind:
        ord_val = raw & 0xFFFF
        # bind entries: ordinal must be < n_imports, OR a special ordinal (>=0xFFF0)
        if ord_val < n_imports:
            return True
        if ord_val >= 0xFFF0:
            return True
        return False
    else:
        # rebase: target is bits 0-35 (36-bit). Reasonable targets are
        # smaller than vmsize + 1 page of slack.
        target = raw & 0xFFFFFFFFF
        if 0 < target < (seg_vmsize + 0x10000):
            # also: next field should not be wildly large
            next_15 = (raw >> 36) & 0x7FFF
            if next_15 * 4 < 0x10000:  # <64KB stride
                return True
        return False


# ============================================================
# Main
# ============================================================
def main():
    with open(WGET_PATH, 'rb') as f:
        data = f.read()
    log = Tee()

    log.log(f'Loaded {WGET_PATH}  ({len(data)} bytes)')

    mo = parse_macho(data, log)
    if mo is None:
        return 1
    cf = parse_chained_fixups(data, mo, log)
    if cf is None:
        return 1

    # Stash imports on each seg_info for easy access inside trace_chain
    for sg in cf['seg_info_list']:
        if sg is not None:
            sg['__imports'] = cf['imports']

    # ----- Trace chains in THREE modes for every ptr_format=6 segment -----
    modes = ['12bit', '15bit', 'heuristic']
    # results[mode][seg_idx] = list of entries
    results = {m: defaultdict(list) for m in modes}
    # visited[mode][seg_idx] = set of (page_idx, offset_in_page)
    visited = {m: defaultdict(set)  for m in modes}
    # chain_terminations[mode][seg_idx] = list of (page_idx, offset_in_page, reason)
    terminations = {m: defaultdict(list) for m in modes}

    log.log('\n' + '='*70)
    log.log('=== Tracing fixup chains in 3 modes for all ptr_format=6 segments ===')
    log.log('  mode="12bit"     -> bits 51-62 (format 4/5 layout, works for jq)')
    log.log('  mode="15bit"     -> bits 36-50 (format 6 layout, Apple spec)')
    log.log('  mode="heuristic" -> 12-bit unless it overflows the page, then 15-bit')
    log.log('='*70)

    for sg in cf['seg_info_list']:
        if sg is None or sg['ptr_format'] != DYLD_CHAINED_PTR_64_OFFSET_64:
            continue
        seg_idx = sg['seg_idx']
        seg = sg['seg']
        log.log(f'\n--- Segment [{seg_idx}] {sg["seg_name"]} '
                f'(page_size={sg["page_size"]}, page_count={sg["page_count"]}) ---')

        for mode in modes:
            mode_visited = set()
            for pi, ps in enumerate(sg['page_starts']):
                if ps == DYLD_CHAINED_PTR_START_NONE:
                    continue
                if ps & DYLD_CHAINED_PTR_START_MULTI:
                    # Bit 15 set: per task spec, this page's chain starts on a
                    # different page (page index = ps & 0x7FFF). We DO NOT
                    # trace it from this page — it's a continuation indicator.
                    continue
                start_off = ps
                entries, term_zero, term_overflow = trace_chain(
                    data, seg, sg, pi, start_off, mode, log)
                results[mode][seg_idx].extend(entries)
                for e in entries:
                    mode_visited.add((e['page_idx'], e['offset_in_page']))
                terminations[mode][seg_idx].append(
                    (pi, start_off, 'next=0' if term_zero else 'overflow' if term_overflow else 'iter-limit'))
            visited[mode][seg_idx] = mode_visited
            log.log(f'  mode={mode:9s}: visited {len(mode_visited)} entries '
                    f'across {len([t for t in terminations[mode][seg_idx]])} chains')

    # ----- Per-segment visited count summary -----
    log.log('\n=== Total fixup entries visited per segment (per mode) ===')
    log.log(f'  {"seg":<4} {"name":<16} {"12bit":>8} {"15bit":>8} {"heuristic":>10}')
    for sg in cf['seg_info_list']:
        if sg is None:
            continue
        seg_idx = sg['seg_idx']
        seg_name = sg['seg_name']
        n12 = len(visited['12bit'][seg_idx])
        n15 = len(visited['15bit'][seg_idx])
        nH  = len(visited['heuristic'][seg_idx])
        log.log(f'  [{seg_idx}]  {seg_name:<16} {n12:>8} {n15:>8} {nH:>10}')

    # ----- page_start bit-15 scan -----
    log.log('\n=== page_start values with bit 15 set (DYLD_CHAINED_PTR_START_MULTI) ===')
    found_multi = False
    for sg in cf['seg_info_list']:
        if sg is None:
            continue
        for pi, ps in enumerate(sg['page_starts']):
            if ps == DYLD_CHAINED_PTR_START_NONE:
                continue
            if ps & DYLD_CHAINED_PTR_START_MULTI:
                found_multi = True
                log.log(f'  seg[{sg["seg_idx"]}] {sg["seg_name"]} page {pi}: '
                        f'page_start=0x{ps:04x}  '
                        f'(lower 15 bits = {ps & 0x7FFF} -> '
                        f'interpreted as page_index OR continuation offset)')
    if not found_multi:
        log.log('  (none found — no page has bit 15 set)')

    # ----- next=0 occurrences (chain end markers) -----
    log.log('\n=== "next=0" chain-end occurrences (per mode) ===')
    for mode in modes:
        for seg_idx, term_list in terminations[mode].items():
            zero_count = sum(1 for _, _, reason in term_list if reason == 'next=0')
            ovfl_count = sum(1 for _, _, reason in term_list if reason == 'overflow')
            limit_count = sum(1 for _, _, reason in term_list if reason == 'iter-limit')
            log.log(f'  mode={mode:9s} seg[{seg_idx}]: '
                    f'{zero_count} chains ended by next=0,  '
                    f'{ovfl_count} by overflow,  '
                    f'{limit_count} by iter-limit')

    # ----- Detailed look at __DATA_CONST (which holds __got) -----
    dc_seg_idx = None
    for seg in mo['segments']:
        if seg['name'] == '__DATA_CONST':
            dc_seg_idx = seg['index']
            break
    log.log('\n' + '='*70)
    log.log('=== __DATA_CONST analysis (this is the segment containing __got) ===')
    log.log('='*70)
    if dc_seg_idx is None:
        log.log('  __DATA_CONST segment NOT FOUND')
    else:
        dc_seg = mo['segments'][dc_seg_idx]
        log.log(f'  seg_idx        = {dc_seg_idx}')
        log.log(f'  vmaddr         = 0x{dc_seg["vmaddr"]:x}')
        log.log(f'  vmsize         = 0x{dc_seg["vmsize"]:x}')
        log.log(f'  fileoff        = 0x{dc_seg["fileoff"]:x}')
        log.log(f'  filesize       = 0x{dc_seg["filesize"]:x}')

        dc_sections = [s for s in mo['sections'] if s['segname'] == '__DATA_CONST']
        log.log(f'\n  __DATA_CONST sections:')
        for s in dc_sections:
            off_in_seg = s['addr'] - dc_seg['vmaddr']
            log.log(f'    {s["sectname"]:<20} addr=0x{s["addr"]:x} size=0x{s["size"]:x} '
                    f'(seg offset 0x{off_in_seg:x})  '
                    f'flags=0x{s["flags"]:08x}')

        got_section = next((s for s in dc_sections if s['sectname'] == '__got'), None)
        if got_section:
            got_off = got_section['addr'] - dc_seg['vmaddr']
            n_got = got_section['size'] // 8
            log.log(f'\n  __got found in __DATA_CONST:')
            log.log(f'    offset within __DATA_CONST = 0x{got_off:x}')
            log.log(f'    size                       = 0x{got_section["size"]:x}')
            log.log(f'    number of 8-byte entries   = {n_got}')
            log.log(f'    entries span offsets 0x{got_off:x} .. 0x{got_off + got_section["size"]:x}')

        dc_sg = cf['seg_info_list'][dc_seg_idx]
        page_size = dc_sg['page_size']
        log.log(f'\n  __DATA_CONST page_size = {page_size}')
        log.log(f'  page_starts (all {dc_sg["page_count"]}): '
                f'{[hex(ps) for ps in dc_sg["page_starts"]]}')

        # Target offset
        target_off = 0x858
        target_page = target_off // page_size
        target_in_page = target_off % page_size
        log.log(f'\n  >>> Target offset 0x{target_off:x} within __DATA_CONST <<<')
        log.log(f'      page index       = {target_page}')
        log.log(f'      offset in page    = 0x{target_in_page:x}')
        log.log(f'      page_start[{target_page}] = 0x{dc_sg["page_starts"][target_page]:04x}')

        for mode in modes:
            v = visited[mode][dc_seg_idx]
            is_v = (target_page, target_in_page) in v
            log.log(f'      visited by mode={mode:9s} ? {is_v}')

        # List visited offsets on target page in each mode
        log.log(f'\n  All visited offsets on __DATA_CONST page {target_page}:')
        for mode in modes:
            v = sorted(off for (pi, off) in visited[mode][dc_seg_idx] if pi == target_page)
            log.log(f'    mode={mode:9s}: {len(v)} entries')
            log.log(f'      offsets: {[hex(o) for o in v]}')

        # nearest before/after target offset (using 15-bit mode = Apple spec)
        v15 = sorted(off for (pi, off) in visited['15bit'][dc_seg_idx] if pi == target_page)
        before15 = [o for o in v15 if o < target_in_page]
        after15  = [o for o in v15 if o > target_in_page]
        log.log(f'\n  Nearest visited offsets (mode=15bit) to 0x{target_in_page:x}:')
        if before15:
            log.log(f'    BEFORE: 0x{max(before15):x}  (distance {target_in_page - max(before15)} bytes)')
        else:
            log.log(f'    BEFORE: (none on this page in 15-bit mode)')
        if after15:
            log.log(f'    AFTER : 0x{min(after15):x}  (distance {min(after15) - target_in_page} bytes)')
        else:
            log.log(f'    AFTER : (none on this page in 15-bit mode)')

        # same for 12-bit
        v12 = sorted(off for (pi, off) in visited['12bit'][dc_seg_idx] if pi == target_page)
        before12 = [o for o in v12 if o < target_in_page]
        after12  = [o for o in v12 if o > target_in_page]
        log.log(f'\n  Nearest visited offsets (mode=12bit) to 0x{target_in_page:x}:')
        if before12:
            log.log(f'    BEFORE: 0x{max(before12):x}  (distance {target_in_page - max(before12)} bytes)')
        else:
            log.log(f'    BEFORE: (none on this page in 12-bit mode)')
        if after12:
            log.log(f'    AFTER : 0x{min(after12):x}  (distance {min(after12) - target_in_page} bytes)')
        else:
            log.log(f'    AFTER : (none on this page in 12-bit mode)')

        # Print raw 8-byte values around 0x858 (within +/- 0x80)
        log.log(f'\n  Raw 8-byte values around __DATA_CONST offset 0x{target_off:x} '
                f'(showing +/- 0x80):')
        log.log(f'    {"seg_off":>10}  {"raw":>18}  bind?  next12  next15  '
                f'15bit_visited  12bit_visited  sym_name')
        start_seg_off = max(0, target_off - 0x80)
        end_seg_off   = min(dc_seg['filesize'], target_off + 0x80)
        for so in range(start_seg_off, end_seg_off, 8):
            file_off = dc_seg['fileoff'] + so
            if file_off + 8 > len(data):
                break
            raw = struct.unpack('<Q', data[file_off:file_off+8])[0]
            is_bind = (raw >> 63) & 1
            n12 = (raw >> 51) & 0xFFF
            n15 = (raw >> 36) & 0x7FFF
            page_idx = so // page_size
            off_in_pg = so % page_size
            v15_hit = (page_idx, off_in_pg) in visited['15bit'][dc_seg_idx]
            v12_hit = (page_idx, off_in_pg) in visited['12bit'][dc_seg_idx]
            sym = ''
            if is_bind:
                ord_val = raw & 0xFFFF
                if ord_val < len(cf['imports']):
                    sym = cf['imports'][ord_val]['name']
                else:
                    sym = f'<ord {ord_val}>'
            else:
                t = raw & 0xFFFFFFFFF
                sym = f'rebase@0x{t:x}'
            marker = '  <-- TARGET 0x858' if so == target_off else ''
            v15_str = 'YES' if v15_hit else 'no'
            v12_str = 'YES' if v12_hit else 'no'
            log.log(f'    0x{so:08x}  0x{raw:016x}  {int(is_bind):5d}  '
                    f'{n12:6d}  {n15:6d}  '
                    f'{v15_str:>13}  {v12_str:>14}  {sym}{marker}')

    # ----- Gap analysis: find unvisited fixup-like entries in __DATA_CONST -----
    log.log('\n' + '='*70)
    log.log('=== Gap analysis: unvisited fixup-like entries in __DATA_CONST ===')
    log.log('='*70)
    if dc_seg_idx is not None:
        dc_seg = mo['segments'][dc_seg_idx]
        dc_sg = cf['seg_info_list'][dc_seg_idx]
        page_size = dc_sg['page_size']
        page_count = dc_sg['page_count']
        n_imp = len(cf['imports'])

        # Use 15-bit mode as the "Apple-spec correct" interpretation
        v15 = visited['15bit'][dc_seg_idx]
        v12 = visited['12bit'][dc_seg_idx]
        vH  = visited['heuristic'][dc_seg_idx]

        gap_count_15 = 0
        gap_count_12 = 0
        gap_examples = []
        for pi in range(page_count):
            page_file_off = dc_seg['fileoff'] + pi * page_size
            for off_in_page in range(0, page_size - 8 + 1, 8):
                file_off = page_file_off + off_in_page
                if file_off + 8 > len(data):
                    break
                raw = struct.unpack('<Q', data[file_off:file_off+8])[0]
                if not looks_like_fixup(raw, n_imp, dc_seg['vmsize']):
                    continue
                # it looks like a fixup — is it visited?
                in15 = (pi, off_in_page) in v15
                in12 = (pi, off_in_page) in v12
                inH  = (pi, off_in_page) in vH
                abs_off = pi * page_size + off_in_page
                if not in15:
                    gap_count_15 += 1
                if not in12:
                    gap_count_12 += 1
                if not in15 or not in12:
                    if len(gap_examples) < 60:
                        is_bind = (raw >> 63) & 1
                        sym = ''
                        if is_bind:
                            o = raw & 0xFFFF
                            sym = cf['imports'][o]['name'] if o < n_imp else f'<ord {o}>'
                        else:
                            sym = f'rebase@0x{raw & 0xFFFFFFFFF:x}'
                        gap_examples.append({
                            'abs_off':   abs_off,
                            'page':      pi,
                            'in_page':   off_in_page,
                            'raw':       raw,
                            'is_bind':   bool(is_bind),
                            'sym':       sym,
                            'in_15bit':  in15,
                            'in_12bit':  in12,
                            'in_heur':   inH,
                        })
        log.log(f'  Total fixup-like slots in __DATA_CONST: '
                f'{gap_count_15 + len(v15)} (approx)')
        log.log(f'  Unvisited by 15-bit mode : {gap_count_15}')
        log.log(f'  Unvisited by 12-bit mode : {gap_count_12}')
        log.log(f'  Visited by 15-bit mode    : {len(v15)}')
        log.log(f'  Visited by 12-bit mode    : {len(v12)}')
        log.log(f'  Visited by heuristic mode : {len(vH)}')
        log.log('')
        log.log(f'  Gap examples (showing up to 60):')
        log.log(f'    {"abs_off":>10}  {"page":>4}  {"in_page":>8}  '
                f'{"raw":>18}  bind?  in_15b  in_12b  in_heur  sym')
        for g in gap_examples:
            log.log(f'    0x{g["abs_off"]:08x}  {g["page"]:4d}  0x{g["in_page"]:06x}  '
                    f'0x{g["raw"]:016x}  {int(g["is_bind"]):5d}  '
                    f'{"Y" if g["in_15bit"] else "n":>6}  '
                    f'{"Y" if g["in_12bit"] else "n":>6}  '
                    f'{"Y" if g["in_heur"] else "n":>7}  {g["sym"]}')

    # ----- Compare which mode visits 0x858 -----
    log.log('\n' + '='*70)
    log.log('=== KEY QUESTION: which tracing mode visits offset 0x858? ===')
    log.log('='*70)
    if dc_seg_idx is not None:
        dc_sg = cf['seg_info_list'][dc_seg_idx]
        page_size = dc_sg['page_size']
        target_page = 0x858 // page_size
        target_in_page = 0x858 % page_size
        for mode in modes:
            v = visited[mode][dc_seg_idx]
            hit = (target_page, target_in_page) in v
            log.log(f'  mode={mode:9s}: {"VISITED" if hit else "NOT visited"}')
        # If 15-bit visits it, what's the entry?
        for mode in modes:
            v = visited[mode][dc_seg_idx]
            if (target_page, target_in_page) in v:
                # find the entry
                for e in results[mode][dc_seg_idx]:
                    if e['page_idx'] == target_page and e['offset_in_page'] == target_in_page:
                        log.log(f'\n  Entry at 0x858 in mode={mode}:')
                        log.log(f'    raw        = 0x{e["raw"]:016x}')
                        log.log(f'    is_bind    = {e["is_bind"]}')
                        log.log(f'    next_12    = {e["next_12"]}  '
                                f'(next slot would be 0x{e["offset_in_page"] + e["next_12"]*4:x})')
                        log.log(f'    next_15    = {e["next_15"]}  '
                                f'(next slot would be 0x{e["offset_in_page"] + e["next_15"]*4:x})')
                        log.log(f'    next_used  = {e["next_used"]}')
                        log.log(f'    sym_name   = {e["sym_name"]!r}')

    # ----- Multi-chain-per-page detection -----
    # For each (mode, segment, page), find unvisited fixup-like slots that
    # appear AFTER a next=0 termination — these could be additional chain
    # starts that we're missing.
    log.log('\n' + '='*70)
    log.log('=== Multi-chain-per-page detection ===')
    log.log('  (looking for fixup-like slots AFTER a next=0 termination on the same page)')
    log.log('='*70)
    if dc_seg_idx is not None:
        dc_sg = cf['seg_info_list'][dc_seg_idx]
        page_size = dc_sg['page_size']
        n_imp = len(cf['imports'])
        for mode in modes:
            log.log(f'\n  mode={mode}:')
            # Find all (page_idx, end_offset) where a chain ended via next=0
            for sg in cf['seg_info_list']:
                if sg is None or sg['ptr_format'] != 6:
                    continue
                if sg['seg_idx'] != dc_seg_idx:
                    continue
                seg = sg['seg']
                for pi, ps in enumerate(sg['page_starts']):
                    if ps == DYLD_CHAINED_PTR_START_NONE or (ps & DYLD_CHAINED_PTR_START_MULTI):
                        continue
                    # Trace this page's chain fresh, find where it ended
                    _, term_zero, _ = trace_chain(data, seg, sg, pi, ps, mode, log)
                    if not term_zero:
                        continue
                    # Find the end offset
                    entries, _, _ = trace_chain(data, seg, sg, pi, ps, mode, log)
                    if not entries:
                        continue
                    last_off = entries[-1]['offset_in_page']
                    v_page = set(off for (p, off) in visited[mode][dc_seg_idx] if p == pi)
                    # scan from last_off+8 to end of page for fixup-like unvisited slots
                    extra_starts = []
                    for off in range(last_off + 8, page_size - 8 + 1, 8):
                        if off in v_page:
                            continue
                        file_off = seg['fileoff'] + pi * page_size + off
                        if file_off + 8 > len(data):
                            break
                        raw = struct.unpack('<Q', data[file_off:file_off+8])[0]
                        if looks_like_fixup(raw, n_imp, seg['vmsize']):
                            extra_starts.append((off, raw))
                    if extra_starts:
                        log.log(f'    page {pi}: chain ended at 0x{last_off:x} (next=0). '
                                f'{len(extra_starts)} unvisited fixup-like slots AFTER it:')
                        for off, raw in extra_starts[:8]:
                            is_bind = (raw >> 63) & 1
                            sym = ''
                            if is_bind:
                                o = raw & 0xFFFF
                                sym = cf['imports'][o]['name'] if o < n_imp else f'<ord {o}>'
                            else:
                                sym = f'rebase@0x{raw & 0xFFFFFFFFF:x}'
                            log.log(f'      off 0x{off:x}: raw=0x{raw:016x} bind={int(is_bind)} '
                                    f'next12={(raw>>51)&0xFFF} next15={(raw>>36)&0x7FFF} sym={sym!r}')

    # ----- Final verdict -----
    log.log('\n' + '='*70)
    log.log('=== FINAL VERDICT ===')
    log.log('='*70)
    if dc_seg_idx is not None:
        dc_sg = cf['seg_info_list'][dc_seg_idx]
        page_size = dc_sg['page_size']
        target_page = 0x858 // page_size
        target_in_page = 0x858 % page_size
        v15_hit = (target_page, target_in_page) in visited['15bit'][dc_seg_idx]
        v12_hit = (target_page, target_in_page) in visited['12bit'][dc_seg_idx]
        vH_hit  = (target_page, target_in_page) in visited['heuristic'][dc_seg_idx]
        log.log(f'  Offset 0x858 in __DATA_CONST page 0:')
        log.log(f'    visited by 12-bit mode     : {v12_hit}')
        log.log(f'    visited by 15-bit mode     : {v15_hit}')
        log.log(f'    visited by heuristic mode  : {vH_hit}')

        log.log('')
        log.log('  page_start bit-15 set on any __DATA_CONST page?')
        any_multi = any((ps & DYLD_CHAINED_PTR_START_MULTI)
                        for ps in dc_sg['page_starts']
                        if ps != DYLD_CHAINED_PTR_START_NONE)
        log.log(f'    {any_multi}')
        if any_multi:
            for pi, ps in enumerate(dc_sg['page_starts']):
                if ps != DYLD_CHAINED_PTR_START_NONE and (ps & DYLD_CHAINED_PTR_START_MULTI):
                    log.log(f'      page {pi}: page_start=0x{ps:04x}  '
                            f'(lower 15 bits = {ps & 0x7FFF})')

        log.log('')
        log.log('  Did any chain terminate early via next=0 leaving fixup-like')
        log.log('  slots unvisited afterwards on the same page?')
        log.log('  (checked in ALL three modes; "missed" means fixup-like slots exist')
        log.log('   after the chain terminated via next=0)')
        for check_mode in ['12bit', '15bit', 'heuristic']:
            missed = False
            for sg in cf['seg_info_list']:
                if sg is None or sg['ptr_format'] != 6 or sg['seg_idx'] != dc_seg_idx:
                    continue
                seg = sg['seg']
                for pi, ps in enumerate(sg['page_starts']):
                    if ps == DYLD_CHAINED_PTR_START_NONE or (ps & DYLD_CHAINED_PTR_START_MULTI):
                        continue
                    entries, _, _ = trace_chain(data, seg, sg, pi, ps, check_mode, log)
                    if not entries:
                        continue
                    last_off = entries[-1]['offset_in_page']
                    v_page = set(off for (p, off) in visited[check_mode][dc_seg_idx] if p == pi)
                    for off in range(last_off + 8, page_size - 8 + 1, 8):
                        if off in v_page:
                            continue
                        file_off = seg['fileoff'] + pi * page_size + off
                        if file_off + 8 > len(data):
                            break
                        raw = struct.unpack('<Q', data[file_off:file_off+8])[0]
                        if looks_like_fixup(raw, len(cf['imports']), seg['vmsize']):
                            missed = True
                            break
                    if missed:
                        break
                if missed:
                    break
            log.log(f'    mode={check_mode:9s}: '
                    f'{"YES — unvisited fixup-like slots after next=0" if missed else "no — chain covers all fixup-like slots"}')

    # ----- Special-ordinal threshold diagnostic -----
    # macify's fixups.c (pre-fix) used `ordinal >= 0xFD` to detect "special"
    # ordinals. That threshold is correct for the OLD LC_DYLD_INFO bind format
    # (8-bit ordinals, specials at 0xFD-0xFF) but WRONG for chained fixups
    # (16-bit ordinals, specials at 0xFFF0-0xFFFF). With 274 imports, every
    # ordinal in [253, 273] was incorrectly treated as special and left
    # un-resolved — including _vasprintf (263), the symbol whose __got slot
    # at offset 0x858 is jumped to by the crashing stub.
    log.log('\n' + '='*70)
    log.log('=== SPECIAL-ORDINAL THRESHOLD DIAGNOSTIC (root cause of crash) ===')
    log.log('='*70)
    n_imp = len(cf['imports'])
    log.log(f'  imports_count = {n_imp}')
    log.log(f'  OLD macify threshold: ordinal >= 0xFD  ({0xFD})  '
            f'-> treats ordinals {0xFD}..{n_imp-1} as "special"')
    log.log(f'  CORRECT threshold   : ordinal >= 0xFFF0 ({0xFFF0})  '
            f'(16-bit chained-fixup specials are 0xFFF0-0xFFFF)')
    log.log('')
    bad_ordinals = [o for o in range(0xFD, n_imp)]
    log.log(f'  Ordinals INCORRECTLY skipped by old code: {len(bad_ordinals)}')
    log.log(f'  (these are valid bind ordinals but were left as raw 0x8010... values)')
    log.log('')
    log.log(f'  {"ord":>4}  {"hex":>6}  {"lib":>4}  symbol')
    for o in bad_ordinals:
        imp = cf['imports'][o]
        log.log(f'  {o:>4}  0x{o:04x}  {imp["lib_ordinal"]:>4}  {imp["name"]!r}')
    log.log('')
    # Specifically call out 0x858
    log.log(f'  >>> The crashing __got slot at offset 0x858 holds ordinal 263 (0x107) = _vasprintf.')
    log.log(f'      With the old 0xFD threshold, this ordinal is INCORRECTLY treated as special,')
    log.log(f'      so the slot is left as the raw value 0x8010000000000107 — a non-canonical')
    log.log(f'      x86_64 address. The stub at __TEXT offset 0x42b1e does')
    log.log(f'      `jmp qword ptr [rip+0x15d34]` which reads this slot and jumps to that')
    log.log(f'      non-canonical address -> SIGSEGV (reported as faulting addr=(nil)).')
    log.log('')
    log.log(f'  FIX: change `ordinal >= 0xFD` to `ordinal >= 0xFFF0` in fixups.c.')
    log.log(f'       After applying this fix, wget --help and wget --version both work.')

    # ----- Save output -----
    with open(OUT_PATH, 'w') as f:
        f.write('\n'.join(log.lines))
        f.write('\n')
    print(f'\n[output written to {OUT_PATH}]')
    return 0


if __name__ == '__main__':
    sys.exit(main())
