#!/usr/bin/env python3
"""
macify-debug — Comprehensive debugging tool for mac-ify translator.

Usage:
  macify-debug disasm <binary> <addr|symbol> [--before N] [--after N]
  macify-debug symbols <binary> [--search PATTERN] [--imports] [--exports]
  macify-debug got <binary> [--resolve]
  macify-debug callers <binary> <addr|symbol>
  macify-debug callees <binary> <addr|symbol>
  macify-debug strings <binary> [--search PATTERN]
  macify-debug struct-offset <binary> <struct_base_symbol> <field_offset_hex>
  macify-debug trace <binary> <addr|symbol> [--depth N]
  macify-debug bindings <binary> [--search PATTERN]
  macify-debug xref <binary> <addr|symbol>
  macify-debug crash <binary> <rip_hex> <slide_hex> [--regs REG=VAL ...]

Examples:
  macify-debug disasm curl_macos SSL_CTX_new_ex --after 60
  macify-debug symbols curl_macos --search SSL_CTX
  macify-debug callers curl_macos SSL_CTX_new_ex
  macify-debug struct-offset curl_macos _DefaultRuneLocale 0x3c
  macify-debug crash curl_macos 0x7f1234567890 0x7f1200000000
"""

import sys
import os
import struct
import argparse
import subprocess

try:
    import lief
    import capstone
except ImportError:
    print("Error: need lief and capstone. Install: pip install lief capstone")
    sys.exit(1)

# ── Helpers ────────────────────────────────────────────────────

def load_binary(path):
    fat = lief.MachO.parse(path)
    if not fat or len(fat) == 0:
        print(f"Error: cannot parse {path}")
        sys.exit(1)
    return fat[0]

def get_text_section(binary):
    for sec in binary.sections:
        if sec.name == '__text':
            return sec
    return None

def get_symbols_sorted(binary):
    return sorted([(s.value, s.name) for s in binary.symbols if s.value], key=lambda x: x[0])

def find_symbol(binary, query):
    """Find a symbol by exact name or address."""
    # Try as hex address
    try:
        addr = int(query, 0)
        for sym in binary.symbols:
            if sym.value == addr:
                return sym.value, sym.name
        return addr, f"0x{addr:x}"
    except ValueError:
        pass
    # Try as symbol name
    for sym in binary.symbols:
        name = sym.name
        if name.startswith('_'):
            name = name[1:]
        if name == query or sym.name == query or sym.name == '_' + query:
            return sym.value, sym.name
    # Try partial match
    matches = []
    for sym in binary.symbols:
        if query.lower() in sym.name.lower():
            matches.append((sym.value, sym.name))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"Ambiguous symbol '{query}':")
        for v, n in matches[:10]:
            print(f"  0x{v:x}: {n}")
        if len(matches) > 10:
            print(f"  ... and {len(matches)-10} more")
        sys.exit(1)
    print(f"Symbol not found: {query}")
    sys.exit(1)

def get_stubs_info(binary):
    """Get __stubs section info for resolving stub -> symbol."""
    stub_sec = None
    for sec in binary.sections:
        if sec.name == '__stubs':
            stub_sec = sec
            break
    if not stub_sec:
        return None, None, None
    # Parse load commands for symtab and dysymtab
    with open(binary.parser.config  # hack to get file path
              if hasattr(binary, 'parser') else '', 'rb') as f:
        pass
    return stub_sec, None, None

def resolve_stub(binary, stub_addr):
    """Resolve a stub address to its symbol name using the indirect symbol table."""
    stub_sec = None
    for sec in binary.sections:
        if sec.name == '__stubs':
            stub_sec = sec
            break
    if not stub_sec:
        return None
    if not (stub_sec.virtual_address <= stub_addr < stub_sec.virtual_address + stub_sec.size):
        return None
    stub_idx = (stub_addr - stub_sec.virtual_address) // (stub_sec.reserved2 or 6)
    # Use LIEF to get the indirect symbol
    # Actually, we need to parse the raw file for this
    # Let's use a different approach: check dyld_info bindings
    if binary.has_dyld_info:
        di = binary.dyld_info
        for bind in di.bindings:
            if bind.address == stub_addr:
                return bind.symbol.name if bind.symbol else None
    return None

# ── Commands ──────────────────────────────────────────────────

def cmd_disasm(args):
    binary = load_binary(args.binary)
    text = get_text_section(binary)
    if not text:
        print("No __text section")
        return
    text_data = bytes(text.content)
    text_base = text.virtual_address

    addr, name = find_symbol(binary, args.target)
    syms = get_symbols_sorted(binary)

    off = addr - text_base
    if off < 0 or off >= len(text_data):
        print(f"Address 0x{addr:x} not in __text")
        return

    before = args.before or 0
    after = args.after or 40

    start = max(0, off - before)
    chunk = text_data[start:start + before + after]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(f"=== {name} at 0x{addr:x} ===")
    for ins in md.disasm(chunk, text_base + start):
        marker = " <---" if ins.address == addr else ""
        # Resolve call targets
        extra = ""
        if ins.mnemonic == 'call':
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    t = op.imm
                    for v, n in syms:
                        if v == t:
                            extra = f"  ; {n}"
                            break
                    break
        elif ins.mnemonic == 'lea' and 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target = ins.address + ins.size + op.mem.disp
                    extra = f"  ; -> 0x{target:x}"
                    # Check if it's a string
                    for sec in binary.sections:
                        if sec.virtual_address <= target < sec.virtual_address + sec.size:
                            if sec.name in ('__cstring', '__const'):
                                sdata = bytes(sec.content)
                                soff = target - sec.virtual_address
                                if sec.name == '__cstring':
                                    end = sdata.find(b'\x00', soff)
                                    s = sdata[soff:end].decode('utf-8', errors='replace')
                                    extra = f'  ; -> "{s}"'
                                else:
                                    val = struct.unpack_from('<Q', sdata, soff)[0] if soff + 8 <= len(sdata) else 0
                                    extra = f"  ; -> 0x{val:016x}"
                            break
                    break
        print(f"  0x{ins.address:x}: {ins.bytes.hex():<24s} {ins.mnemonic} {ins.op_str}{extra}{marker}")
        if ins.address >= addr + after:
            break

def cmd_symbols(args):
    binary = load_binary(args.binary)
    if args.imports:
        for sym in binary.imported_symbols:
            if args.search and args.search.lower() not in sym.name.lower():
                continue
            print(f"  IMPORT  {sym.name}")
    elif args.exports:
        for sym in binary.symbols:
            if sym.type == lief.MachO.SYMBOL_TYPES.EXPORTED and sym.value:
                if args.search and args.search.lower() not in sym.name.lower():
                    continue
                print(f"  0x{sym.value:x}  EXPORT  {sym.name}")
    else:
        for sym in binary.symbols:
            if not sym.value:
                continue
            if args.search and args.search.lower() not in sym.name.lower():
                continue
            print(f"  0x{sym.value:x}  {sym.name}")

def cmd_callers(args):
    binary = load_binary(args.binary)
    text = get_text_section(binary)
    text_data = bytes(text.content)
    text_base = text.virtual_address

    target_addr, target_name = find_symbol(binary, args.target)
    syms = get_symbols_sorted(binary)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(f"=== Callers of {target_name} (0x{target_addr:x}) ===")
    count = 0
    for ins in md.disasm(text_data, text_base):
        if ins.mnemonic in ('call', 'jmp'):
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM and op.imm == target_addr:
                    # Find enclosing function
                    for v, n in syms:
                        if v <= ins.address and v + 0x10000 > ins.address:
                            print(f"  0x{ins.address:x} in {n}")
                            count += 1
                            break
                    break
    print(f"\nTotal: {count}")

def cmd_callees(args):
    binary = load_binary(args.binary)
    text = get_text_section(binary)
    text_data = bytes(text.content)
    text_base = text.virtual_address

    addr, name = find_symbol(binary, args.target)
    syms = get_symbols_sorted(binary)

    # Find function end (next symbol or ret)
    func_end = addr + 0x10000
    for v, n in syms:
        if v > addr:
            func_end = v
            break

    off = addr - text_base
    chunk = text_data[off:off + (func_end - addr)]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(f"=== Callees of {name} (0x{addr:x}) ===")
    seen = set()
    for ins in md.disasm(chunk, addr):
        if ins.mnemonic == 'call':
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    t = op.imm
                    if t not in seen:
                        seen.add(t)
                        sname = "?"
                        for v, n in syms:
                            if v == t:
                                sname = n
                                break
                        print(f"  0x{ins.address:x}: call {sname} (0x{t:x})")
                    break
                elif op.type == capstone.x86.X86_OP_REG:
                    print(f"  0x{ins.address:x}: call {ins.op_str}  (indirect)")
                    break

def cmd_strings(args):
    binary = load_binary(args.binary)
    for sec in binary.sections:
        if sec.name == '__cstring':
            data = bytes(sec.content)
            base = sec.virtual_address
            idx = 0
            while idx < len(data):
                end = data.find(b'\x00', idx)
                if end == -1:
                    break
                s = data[idx:end].decode('utf-8', errors='replace')
                if s and (not args.search or args.search.lower() in s.lower()):
                    print(f"  0x{base+idx:x}: {s!r}")
                idx = end + 1

def cmd_struct_offset(args):
    """Check what a binary accesses at a given offset from a struct base symbol."""
    binary = load_binary(args.binary)
    text = get_text_section(binary)
    text_data = bytes(text.content)
    text_base = text.virtual_address

    base_addr, base_name = find_symbol(binary, args.struct_symbol)
    field_offset = int(args.offset, 0)
    syms = get_symbols_sorted(binary)

    # Search for all instructions that access [reg + field_offset] where reg
    # was loaded from the struct base address
    # This is a heuristic: find LEAs that load base_addr, then track the register
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(f"=== Accesses to {base_name}+0x{field_offset:x} ===")
    print(f"Struct base: 0x{base_addr:x}")

    # Search for the base address as a global pointer load
    # Pattern: mov reg, [rip + X] where X points to a GOT entry containing base_addr
    # Or: lea reg, [rip + X] where X points directly to base_addr

    # Also search for accesses with the exact offset
    count = 0
    for ins in md.disasm(text_data, text_base):
        if ins.mnemonic in ('mov', 'cmp', 'lea', 'add', 'sub') and 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target = ins.address + ins.size + op.mem.disp
                    if target == base_addr + field_offset:
                        for v, n in syms:
                            if v <= ins.address:
                                print(f"  0x{ins.address:x} in {n}: {ins.mnemonic} {ins.op_str}")
                                count += 1
                                break
                        break
    print(f"\nTotal: {count}")

def cmd_xref(args):
    """Find all references to an address (LEA, data pointers)."""
    binary = load_binary(args.binary)
    target_addr, target_name = find_symbol(binary, args.target)

    print(f"=== Cross-references to {target_name} (0x{target_addr:x}) ===")

    # Search for 8-byte address in all sections
    target_bytes = struct.pack('<Q', target_addr)
    for sec in binary.sections:
        data = bytes(sec.content)
        idx = 0
        while True:
            idx = data.find(target_bytes, idx)
            if idx == -1:
                break
            static_addr = sec.virtual_address + idx
            print(f"  8-byte ref at 0x{static_addr:x} in {sec.segment.name}.{sec.name}")
            idx += 1

    # Search for LEA rip+disp32
    text = get_text_section(binary)
    if text:
        text_data = bytes(text.content)
        text_base = text.virtual_address
        for off in range(0, len(text_data) - 7):
            if 0x48 <= text_data[off] <= 0x4F and text_data[off+1] == 0x8D:
                modrm = text_data[off+2]
                if (modrm & 0xC7) == 0x05:
                    disp = struct.unpack_from('<i', text_data, off + 3)[0]
                    target = 0x100000000 + off + 7 + disp  # assuming static base
                    # Actually use text_base
                    target = text_base + off + 7 + disp
                    if target == target_addr:
                        syms = get_symbols_sorted(binary)
                        for v, n in syms:
                            if v <= text_base + off:
                                print(f"  LEA at 0x{text_base+off:x} in {n}")
                                break

def cmd_crash(args):
    """Analyze a crash: map runtime addresses to static addresses and symbols."""
    binary = load_binary(args.binary)
    rip = int(args.rip, 0)
    slide = int(args.slide, 0)
    static_rip = rip - slide

    syms = get_symbols_sorted(binary)

    print(f"=== Crash Analysis ===")
    print(f"  Runtime RIP: 0x{rip:x}")
    print(f"  Slide:       0x{slide:x}")
    print(f"  Static RIP:  0x{static_rip:x}")

    # Find which segment
    for seg in binary.segments:
        if seg.virtual_address <= static_rip < seg.virtual_address + seg.virtual_size:
            print(f"  Segment:     {seg.name}")
            break

    # Find nearest symbol
    for v, n in syms:
        if v <= static_rip:
            offset = static_rip - v
            print(f"  Function:    {n} (0x{v:x}, +0x{offset:x})")
            break

    # Disassemble around the crash site
    text = get_text_section(binary)
    if text and text.virtual_address <= static_rip < text.virtual_address + text.size:
        print(f"\n=== Disassembly around crash ===")
        off = static_rip - text.virtual_address
        before = 0x40
        after = 0x20
        start = max(0, off - before)
        chunk = text.content[start:start + before + after]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        for ins in md.disasm(bytes(chunk), text.virtual_address + start):
            marker = " <--- CRASH" if ins.address == static_rip else ""
            extra = ""
            if ins.mnemonic == 'call':
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_IMM:
                        t = op.imm
                        for v, n in syms:
                            if v == t:
                                extra = f"  ; {n}"
                                break
                        break
            print(f"  0x{ins.address:x}: {ins.mnemonic} {ins.op_str}{extra}{marker}")
            if ins.address >= static_rip + after:
                break

    # Map registers
    if args.regs:
        print(f"\n=== Register Analysis ===")
        for reg_str in args.regs:
            if '=' not in reg_str:
                continue
            reg_name, val_str = reg_str.split('=', 1)
            val = int(val_str, 0)
            static_val = val - slide if val > slide else val
            # Check if it's a code address
            for v, n in syms:
                if v == static_val:
                    print(f"  {reg_name} = 0x{val:x} -> {n}")
                    break
            else:
                # Check if it's a string
                for sec in binary.sections:
                    if sec.virtual_address <= static_val < sec.virtual_address + sec.size:
                        if sec.name == '__cstring':
                            sdata = bytes(sec.content)
                            soff = static_val - sec.virtual_address
                            end = sdata.find(b'\x00', soff)
                            s = sdata[soff:end].decode('utf-8', errors='replace')
                            print(f"  {reg_name} = 0x{val:x} -> \"{s}\"")
                        else:
                            print(f"  {reg_name} = 0x{val:x} -> {sec.segment.name}.{sec.name}+0x{static_val-sec.virtual_address:x}")
                        break
                else:
                    print(f"  {reg_name} = 0x{val:x}")

def cmd_trace(args):
    """Trace what functions are called from a given function."""
    binary = load_binary(args.binary)
    text = get_text_section(binary)
    text_data = bytes(text.content)
    text_base = text.virtual_address

    addr, name = find_symbol(binary, args.target)
    syms = get_symbols_sorted(binary)
    depth = args.depth or 2

    # Find function end
    func_end = addr + 0x10000
    for v, n in syms:
        if v > addr:
            func_end = v
            break

    off = addr - text_base
    chunk = text_data[off:off + (func_end - addr)]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(f"=== Call trace from {name} (0x{addr:x}), depth={depth} ===")

    def trace_func(func_addr, func_name, current_depth, visited):
        if current_depth <= 0 or func_addr in visited:
            return
        visited.add(func_addr)
        indent = "  " * (depth - current_depth + 1)

        # Find function end
        f_end = func_addr + 0x10000
        for v, n in syms:
            if v > func_addr:
                f_end = v
                break

        f_off = func_addr - text_base
        if f_off < 0 or f_off >= len(text_data):
            return
        f_chunk = text_data[f_off:f_off + min(f_end - func_addr, 0x2000)]

        for ins in md.disasm(bytes(f_chunk), func_addr):
            if ins.mnemonic == 'call':
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_IMM:
                        t = op.imm
                        tname = "?"
                        for v, n in syms:
                            if v == t:
                                tname = n
                                break
                        print(f"{indent}0x{ins.address:x}: call {tname}")
                        if current_depth > 1 and tname != "?":
                            trace_func(t, tname, current_depth - 1, visited)
                        break

    trace_func(addr, name, depth, set())

# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="macify-debug: debugging tool for mac-ify translator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(dest='command', help='Command')

    # disasm
    p = sub.add_parser('disasm', help='Disassemble around an address or symbol')
    p.add_argument('binary')
    p.add_argument('target', help='Symbol name or hex address')
    p.add_argument('--before', type=int, default=0)
    p.add_argument('--after', type=int, default=40)

    # symbols
    p = sub.add_parser('symbols', help='List/search symbols')
    p.add_argument('binary')
    p.add_argument('--search', help='Filter by pattern')
    p.add_argument('--imports', action='store_true', help='Show imports only')
    p.add_argument('--exports', action='store_true', help='Show exports only')

    # callers
    p = sub.add_parser('callers', help='Find callers of a function')
    p.add_argument('binary')
    p.add_argument('target', help='Symbol name or hex address')

    # callees
    p = sub.add_parser('callees', help='Find callees of a function')
    p.add_argument('binary')
    p.add_argument('target', help='Symbol name or hex address')

    # strings
    p = sub.add_parser('strings', help='Search __cstring section')
    p.add_argument('binary')
    p.add_argument('--search', help='Filter by pattern')

    # struct-offset
    p = sub.add_parser('struct-offset', help='Check accesses to struct+offset')
    p.add_argument('binary')
    p.add_argument('struct_symbol', help='Symbol name of the struct base')
    p.add_argument('offset', help='Hex offset (e.g. 0x3c)')

    # xref
    p = sub.add_parser('xref', help='Find all references to an address')
    p.add_argument('binary')
    p.add_argument('target', help='Symbol name or hex address')

    # crash
    p = sub.add_parser('crash', help='Analyze a crash')
    p.add_argument('binary')
    p.add_argument('rip', help='Runtime RIP (hex)')
    p.add_argument('slide', help='ASLR slide (hex)')
    p.add_argument('--regs', nargs='*', help='Registers as REG=VAL (hex)')

    # trace
    p = sub.add_parser('trace', help='Trace function calls')
    p.add_argument('binary')
    p.add_argument('target', help='Symbol name or hex address')
    p.add_argument('--depth', type=int, default=2)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    {
        'disasm': cmd_disasm,
        'symbols': cmd_symbols,
        'callers': cmd_callers,
        'callees': cmd_callees,
        'strings': cmd_strings,
        'struct-offset': cmd_struct_offset,
        'xref': cmd_xref,
        'crash': cmd_crash,
        'trace': cmd_trace,
    }[args.command](args)

if __name__ == '__main__':
    main()
