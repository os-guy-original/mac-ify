#!/usr/bin/env python3
"""
gen_macho.py — generates minimal Mach-O x86_64 test binaries.

These binaries use only raw macOS BSD syscalls (no libSystem, no
frameworks). They are designed to be loaded by Mac-ify's loader to
verify that:
  - Mach-O parsing works
  - Segment mapping works
  - The syscall trampoline (UD2 patching + SIGILL handler) correctly
    translates macOS BSD syscall numbers to Linux syscalls
  - The entry jumper sets up the stack and jumps correctly

Each binary is hand-assembled. The bytes below were verified by
cross-referencing the Intel SDM Vol 2 and the macOS syscall table
in <sys/syscall.h> (XNU source).

macOS x86_64 BSD syscall numbers (the high bit 0x2000000 selects the
BSD syscall class on macOS; the low 16 bits are the BSD syscall #):
    1 = exit              4 = write
    5 = open              6 = close
"""

import os
import struct
import sys

# === Mach-O constants ===
MH_MAGIC_64         = 0xFEEDFACF
CPU_TYPE_X86_64     = 0x01000007
CPU_SUBTYPE_X86_64_ALL = 0x80000003
MH_EXECUTE          = 0x02
MH_PIE              = 0x200000
LC_SEGMENT_64       = 0x19
LC_UNIXTHREAD       = 0x05
x86_THREAD_STATE64  = 0x04

VM_PROT_READ        = 0x01
VM_PROT_WRITE       = 0x02
VM_PROT_EXECUTE     = 0x04

PAGE_SIZE           = 0x1000
PAGEZERO_VMSIZE     = 0x1000       # 4 KB null-page guard
TEXT_VMADDR         = PAGEZERO_VMSIZE  # right after PAGEZERO


def align_up(n, a):
    return (n + a - 1) & ~(a - 1)


def mach_header(ncmds, sizeofcmds, flags=0):
    return struct.pack('<IIIIIIII',
        MH_MAGIC_64,
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        MH_EXECUTE,
        ncmds,
        sizeofcmds,
        flags,
        0)


def segment_command_64(segname, vmaddr, vmsize, fileoff, filesize,
                       maxprot, initprot, nsects=0, flags=0):
    name = segname.encode('ascii').ljust(16, b'\0')[:16]
    return struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, 72,
        name,
        vmaddr, vmsize,
        fileoff, filesize,
        maxprot, initprot,
        nsects, flags)


def unixthread(rip, rsp, rax=0, rdi=0, rsi=0, rdx=0):
    """Build an LC_UNIXTHREAD load command for x86_64.

    The thread state is 21 uint64s: rax, rbx, rcx, rdx, rdi, rsi, rbp,
    rsp, r8..r15, rip, rflags, cs, fs, gs.
    """
    state = struct.pack('<21Q',
        rax, 0, 0, rdx, rdi, rsi, 0, rsp,
        0, 0, 0, 0, 0, 0, 0, 0,
        rip, 0x200, 0x2b, 0, 0)
    cmdsize = 16 + len(state)
    return (struct.pack('<IIII',
        LC_UNIXTHREAD, cmdsize, x86_THREAD_STATE64, len(state) // 4)
        + state)


def build_macho(code):
    """Wrap raw code bytes in a minimal Mach-O x86_64 executable."""
    HEADER_SIZE   = 32 + 72 + 72 + 184          # = 360 bytes
    CODE_OFFSET   = align_up(HEADER_SIZE, 16)   # = 368 (16-byte align)
    PAD           = CODE_OFFSET - HEADER_SIZE   # = 8
    TOTAL_SIZE    = CODE_OFFSET + len(code)

    pagezero = segment_command_64(
        '__PAGEZERO',
        vmaddr=0, vmsize=PAGEZERO_VMSIZE,
        fileoff=0, filesize=0,
        maxprot=VM_PROT_READ, initprot=0)

    text_seg = segment_command_64(
        '__TEXT',
        vmaddr=TEXT_VMADDR,
        vmsize=align_up(TOTAL_SIZE, PAGE_SIZE),
        fileoff=0, filesize=TOTAL_SIZE,
        maxprot=VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        initprot=VM_PROT_READ | VM_PROT_EXECUTE)

    entry_rip = TEXT_VMADDR + CODE_OFFSET
    thread = unixthread(rip=entry_rip, rsp=0x7fff0000)

    header = mach_header(
        ncmds=3,
        sizeofcmds=len(pagezero) + len(text_seg) + len(thread))
    padding = b'\x90' * PAD  # NOPs

    return header + pagezero + text_seg + thread + padding + code


# ============================================================
# Test binaries — hand-assembled x86_64 code.
#
# All bytes verified against the Intel SDM Vol 2 instruction
# reference. RIP-relative LEA displacements are computed from the
# END of the LEA instruction to the target.
# ============================================================

def hello_code():
    """Write 'Hello, Mac-ify!\\n' to stdout (16 bytes), then exit 0."""
    msg = b"Hello, Mac-ify!\n"
    assert len(msg) == 16
    # Layout:
    #   0x00: mov eax, 0x2000004      (5)   b8 04 00 00 20
    #   0x05: mov edi, 1              (5)   bf 01 00 00 00
    #   0x0a: lea rsi, [rip + 0x13]   (7)   48 8d 35 13 00 00 00
    #   0x11: mov edx, 16             (5)   ba 10 00 00 00
    #   0x16: syscall                 (2)   0f 05
    #   0x18: mov eax, 0x2000001      (5)   b8 01 00 00 20
    #   0x1d: mov edi, 0              (5)   bf 00 00 00 00
    #   0x22: syscall                 (2)   0f 05
    #   0x24: msg                     (16)
    # LEA disp = 0x24 - 0x11 = 0x13 = 19
    return (
        b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004
        b'\xbf\x01\x00\x00\x00'                          # mov edi, 1
        b'\x48\x8d\x35' + struct.pack('<i', 0x13) +      # lea rsi, [rip + 19]
        b'\xba\x10\x00\x00\x00'                          # mov edx, 16
        b'\x0f\x05'                                       # syscall
        b'\xb8\x01\x00\x00\x20'                          # mov eax, 0x2000001
        b'\xbf\x00\x00\x00\x00'                          # mov edi, 0
        b'\x0f\x05'                                       # syscall
        + msg
    )


def exit42_code():
    """Exit immediately with code 42."""
    return (
        b'\xb8\x01\x00\x00\x20'   # mov eax, 0x2000001  (exit)
        b'\xbf\x2a\x00\x00\x00'   # mov edi, 42
        b'\x0f\x05'               # syscall
    )


def argv_code():
    """Write argv[0] (the binary's own path) to stdout, then a newline, exit 0.

    On macOS x86_64 entry, the stack looks like:
        [rsp+0]  = argc
        [rsp+8]  = argv[0]
        [rsp+16] = argv[1] or NULL
        ...
    """
    # Layout (offsets from start of code):
    #   0x00: mov rsi, [rsp+8]         (5)   48 8b 74 24 08
    #   0x05: mov rcx, rsi             (3)   48 89 f1
    #   0x08: cmp byte [rcx], 0        (3)   80 39 00      .loop:
    #   0x0b: jz +5                    (2)   74 05
    #   0x0d: inc rcx                  (3)   48 ff c1
    #   0x10: jmp -10                  (2)   eb f6         -> 0x08
    #   0x12: sub rcx, rsi             (3)   48 29 f1
    #   0x15: mov rdx, rcx             (3)   48 89 ca
    #   0x18: mov edi, 1               (5)   bf 01 00 00 00
    #   0x1d: mov eax, 0x2000004       (5)   b8 04 00 00 20
    #   0x22: syscall                  (2)   0f 05
    #   0x24: mov eax, 0x2000004       (5)   b8 04 00 00 20
    #   0x29: mov edi, 1               (5)   bf 01 00 00 00
    #   0x2e: lea rsi, [rip + 0x13]    (7)   48 8d 35 13 00 00 00
    #   0x35: mov edx, 1               (5)   ba 01 00 00 00
    #   0x3a: syscall                  (2)   0f 05
    #   0x3c: mov eax, 0x2000001       (5)   b8 01 00 00 20
    #   0x41: mov edi, 0               (5)   bf 00 00 00 00
    #   0x46: syscall                  (2)   0f 05
    #   0x48: newline byte             (1)   0a
    # LEA disp = 0x48 - 0x35 = 0x13 = 19
    return (
        b'\x48\x8b\x74\x24\x08'                          # mov rsi, [rsp+8]
        b'\x48\x89\xf1'                                  # mov rcx, rsi
        b'\x80\x39\x00'                                  # cmp byte [rcx], 0
        b'\x74\x05'                                      # jz +5
        b'\x48\xff\xc1'                                  # inc rcx
        b'\xeb\xf6'                                      # jmp -10
        b'\x48\x29\xf1'                                  # sub rcx, rsi
        b'\x48\x89\xca'                                  # mov rdx, rcx
        b'\xbf\x01\x00\x00\x00'                          # mov edi, 1
        b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004
        b'\x0f\x05'                                       # syscall
        b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004
        b'\xbf\x01\x00\x00\x00'                          # mov edi, 1
        b'\x48\x8d\x35' + struct.pack('<i', 0x13) +      # lea rsi, [rip + 19]
        b'\xba\x01\x00\x00\x00'                          # mov edx, 1
        b'\x0f\x05'                                       # syscall
        b'\xb8\x01\x00\x00\x20'                          # mov eax, 0x2000001
        b'\xbf\x00\x00\x00\x00'                          # mov edi, 0
        b'\x0f\x05'                                       # syscall
        b'\x0a'                                           # '\n'
    )


def compute_code():
    """Compute 1+2+...+10 = 55 in a loop, then exit with code 55.

    This proves native CPU execution is working — the syscall trampoline
    isn't faking the arithmetic.
    """
    # Layout:
    #   0x00: xor rax, rax             (3)   48 31 c0
    #   0x03: mov ecx, 1               (5)   b9 01 00 00 00
    #   0x08: add rax, rcx             (3)   48 01 c8     .loop:
    #   0x0b: inc rcx                  (3)   48 ff c1
    #   0x0e: cmp rcx, 10              (4)   48 83 f9 0a
    #   0x12: jle -12                  (2)   7e f4        -> 0x08
    #   0x14: mov rdi, rax             (3)   48 89 c7
    #   0x17: mov eax, 0x2000001       (5)   b8 01 00 00 20
    #   0x1c: syscall                  (2)   0f 05
    # JLE offset: target 0x08, end-of-jle 0x14, disp = 0x08 - 0x14 = -12 = 0xF4
    return (
        b'\x48\x31\xc0'             # xor rax, rax
        b'\xb9\x01\x00\x00\x00'     # mov ecx, 1
        b'\x48\x01\xc8'             # add rax, rcx
        b'\x48\xff\xc1'             # inc rcx
        b'\x48\x83\xf9\x0a'         # cmp rcx, 10
        b'\x7e\xf4'                 # jle -12
        b'\x48\x89\xc7'             # mov rdi, rax
        b'\xb8\x01\x00\x00\x20'     # mov eax, 0x2000001
        b'\x0f\x05'                 # syscall
    )


def writefile_code():
    """Open /tmp/macify-test.txt, write 'ok\\n', close it, exit 0.

    macOS open flags: O_WRONLY=1, O_CREAT=0x200, O_TRUNC=0x400.
    Combined: 0x601. Mode 0644 = 0x1a4.
    """
    path = b"/tmp/macify-test.txt\x00"  # 21 bytes
    msg  = b"ok\n"                      # 3 bytes

    LEA_RDI_END  = 0x07
    LEA_RSI_END  = 0x25
    PATH_OFFSET  = 0x47
    MSG_OFFSET   = PATH_OFFSET + len(path)  # = 0x5c

    return (
        b'\x48\x8d\x3d' + struct.pack('<i', PATH_OFFSET - LEA_RDI_END) +
        b'\xbe\x01\x06\x00\x00'                          # mov esi, 0x601
        b'\xba\xa4\x01\x00\x00'                          # mov edx, 0x1a4
        b'\xb8\x05\x00\x00\x20'                          # mov eax, 0x2000005
        b'\x0f\x05'                                       # syscall
        b'\x49\x89\xc7'                                  # mov r15, rax
        b'\x4c\x89\xff'                                  # mov rdi, r15
        b'\x48\x8d\x35' + struct.pack('<i', MSG_OFFSET - LEA_RSI_END) +
        b'\xba\x03\x00\x00\x00'                          # mov edx, 3
        b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004
        b'\x0f\x05'                                       # syscall
        b'\x4c\x89\xff'                                  # mov rdi, r15
        b'\xb8\x06\x00\x00\x20'                          # mov eax, 0x2000006
        b'\x0f\x05'                                       # syscall
        b'\xbf\x00\x00\x00\x00'                          # mov edi, 0
        b'\xb8\x01\x00\x00\x20'                          # mov eax, 0x2000001
        b'\x0f\x05'                                       # syscall
        + path + msg
    )


def bench_code():
    """Benchmark: open /dev/null, write 'x' 100,000 times, close, print 'done'.

    This binary is designed to measure the syscall trampoline overhead.
    With the fast path (immediate patching), the 100,000 writes execute
    natively with zero signal-handler overhead. With --no-fast-path, they
    all go through the SIGILL handler (~2us each = ~200ms total).

    NOTE: The loop counter uses rbx, NOT rcx. The `syscall` instruction
    clobbers rcx (saves return rip) and r11 (saves rflags) — this is an
    x86_64 architectural fact. Using rcx as a loop counter across a
    syscall is a bug that happens to work in the SIGILL slow path (which
    preserves rcx) but fails in the fast path (native syscall clobbers
    rcx). Real macOS apps never use rcx/r11 across a syscall.

    Layout (offsets computed dynamically to avoid off-by-one errors):
    """
    path = b"/dev/null\x00"      # 10 bytes
    msg  = b"x"                  # 1 byte
    done = b"done\n"             # 5 bytes

    # Build instruction stream with known lengths, then compute data offsets.
    # Instruction lengths:
    #   mov eax, imm32        = 5  (B8 XX XX XX XX)
    #   lea rdi/rsi, [rip+X]  = 7  (48 8D 3D/35 XX XX XX XX)
    #   mov esi/edx/edi, imm  = 5  (BE/BA/BF XX XX XX XX)
    #   syscall               = 2  (0F 05)
    #   mov r15, rax          = 3  (49 89 C7)
    #   mov rdi, r15          = 3  (4C 89 FF)
    #   mov ebx, imm32        = 5  (BB XX XX XX XX)
    #   dec ebx               = 2  (FF CB)
    #   jne rel8              = 2  (75 XX)

    # Pre-assemble the instruction stream (with placeholder disp bytes),
    # then compute and fill in the displacements.
    code = bytearray()

    # 0x00: open
    code += b'\xb8\x05\x00\x00\x20'                          # mov eax, 0x2000005 (open)
    lea_rdi_pos = len(code)
    code += b'\x48\x8d\x3d\x00\x00\x00\x00'                  # lea rdi, [rip+path] (placeholder)
    code += b'\xbe\x01\x06\x00\x00'                          # mov esi, 0x601
    code += b'\xba\xa4\x01\x00\x00'                          # mov edx, 0x1a4
    code += b'\x0f\x05'                                       # syscall (SLOW - open)
    code += b'\x49\x89\xc7'                                  # mov r15, rax
    code += b'\xbb' + struct.pack('<i', 100000)[:4]          # mov ebx, 100000  (4-byte imm, low 32 bits)

    # .loop:
    loop_start = len(code)
    code += b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004 (write)
    code += b'\x4c\x89\xff'                                  # mov rdi, r15
    lea_rsi_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'                  # lea rsi, [rip+msg] (placeholder)
    code += b'\xba\x01\x00\x00\x00'                          # mov edx, 1
    code += b'\x0f\x05'                                       # syscall (FAST)
    code += b'\xff\xcb'                                       # dec ebx
    jne_pos = len(code)
    code += b'\x75\x00'                                       # jne loop (placeholder)

    # After loop:
    code += b'\xb8\x06\x00\x00\x20'                          # mov eax, 0x2000006 (close)
    code += b'\x4c\x89\xff'                                  # mov rdi, r15
    code += b'\x0f\x05'                                       # syscall (FAST)
    code += b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004 (write)
    code += b'\xbf\x01\x00\x00\x00'                          # mov edi, 1 (stdout)
    lea_done_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'                  # lea rsi, [rip+done] (placeholder)
    code += b'\xba\x05\x00\x00\x00'                          # mov edx, 5
    code += b'\x0f\x05'                                       # syscall (FAST)
    code += b'\xb8\x01\x00\x00\x20'                          # mov eax, 0x2000001 (exit)
    code += b'\xbf\x00\x00\x00\x00'                          # mov edi, 0
    code += b'\x0f\x05'                                       # syscall (SLOW - exit)

    # Data
    path_offset = len(code)
    code += path
    msg_offset = len(code)
    code += msg
    done_offset = len(code)
    code += done

    # Patch LEA displacements (rip-relative, disp = target - end_of_lea)
    def patch_lea(lea_pos, target):
        disp = target - (lea_pos + 7)  # lea is 7 bytes
        struct.pack_into('<i', code, lea_pos + 3, disp)

    patch_lea(lea_rdi_pos, path_offset)
    patch_lea(lea_rsi_pos, msg_offset)
    patch_lea(lea_done_pos, done_offset)

    # Patch JNE displacement (rel8, disp = target - end_of_jne)
    jne_disp = loop_start - (jne_pos + 2)  # jne is 2 bytes
    assert -128 <= jne_disp <= 127, f"jne displacement {jne_disp} out of range"
    code[jne_pos + 1] = jne_disp & 0xFF

    return bytes(code)


def mmap_code():
    """Test mmap flag translation: mmap an anonymous page, write to it, read back.

    macOS MAP_ANON=0x1000 vs Linux MAP_ANONYMOUS=0x20. Without translation,
    Linux sees flags=0x1002 = MAP_PRIVATE|MAP_GROWSDOWN with no MAP_ANONYMOUS,
    and fd=-1 → returns EINVAL. With translation, Linux sees 0x22 =
    MAP_PRIVATE|MAP_ANONYMOUS → succeeds.

    Test: mmap a page, copy "mmap-ok\\n" (8 bytes) into it via rep movsb,
    then write(1, ptr, 8) and exit 0. If mmap fails, write "mmap-FAIL\\n"
    (9 bytes) and exit 1.
    """
    msg  = b"mmap-ok\n"     # 8 bytes
    fail = b"mmap-FAIL\n"   # 9 bytes
    msg_len = len(msg)      # 8
    fail_len = len(fail)    # 9

    code = bytearray()
    # 0x00: mmap setup
    code += b'\xb8\xc5\x00\x00\x20'                       # mov eax, 0x20000C5 (mmap)
    code += b'\x31\xff'                                   # xor edi, edi
    code += b'\xbe\x00\x10\x00\x00'                       # mov esi, 0x1000
    code += b'\xba\x03\x00\x00\x00'                       # mov edx, 3
    code += b'\x41\xba\x02\x10\x00\x00'                   # mov r10d, 0x1002
    code += b'\x41\xb8\xff\xff\xff\xff'                   # mov r8d, -1
    code += b'\x45\x31\xc9'                               # xor r9d, r9d
    code += b'\x0f\x05'                                   # syscall (SLOW)
    # check result
    code += b'\x48\x83\xf8\xff'                           # cmp rax, -1
    jz_pos = len(code)
    code += b'\x0f\x84\x00\x00\x00\x00'                   # jz fail (rel32, placeholder)
    # success path
    code += b'\x49\x89\xc7'                               # mov r15, rax (save ptr)
    lea_msg_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'               # lea rsi, [rip+msg]
    code += b'\x4c\x89\xff'                               # mov rdi, r15
    code += b'\xb9' + struct.pack('<i', msg_len)[:4]       # mov ecx, msg_len
    code += b'\xf3\xa4'                                   # rep movsb
    code += b'\xb8\x04\x00\x00\x20'                       # mov eax, 0x2000004 (write)
    code += b'\xbf\x01\x00\x00\x00'                       # mov edi, 1
    code += b'\x4c\x89\xfe'                               # mov rsi, r15
    code += b'\xba' + struct.pack('<i', msg_len)[:4]       # mov edx, msg_len
    code += b'\x0f\x05'                                   # syscall (FAST)
    code += b'\xb8\x01\x00\x00\x20'                       # mov eax, 0x2000001 (exit)
    code += b'\xbf\x00\x00\x00\x00'                       # mov edi, 0
    code += b'\x0f\x05'                                   # syscall (SLOW)
    # fail path
    fail_path = len(code)
    code += b'\xb8\x04\x00\x00\x20'                       # mov eax, 0x2000004 (write)
    code += b'\xbf\x01\x00\x00\x00'                       # mov edi, 1
    lea_fail_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'               # lea rsi, [rip+fail]
    code += b'\xba' + struct.pack('<i', fail_len)[:4]      # mov edx, fail_len
    code += b'\x0f\x05'                                   # syscall
    code += b'\xb8\x01\x00\x00\x20'                       # mov eax, 0x2000001 (exit)
    code += b'\xbf\x01\x00\x00\x00'                       # mov edi, 1
    code += b'\x0f\x05'                                   # syscall
    # data
    msg_offset = len(code)
    code += msg
    fail_offset = len(code)
    code += fail

    # Patch jz rel32 (disp = target - end_of_jz, jz is 6 bytes)
    struct.pack_into('<i', code, jz_pos + 2, fail_path - (jz_pos + 6))

    # Patch LEA displacements
    struct.pack_into('<i', code, lea_msg_pos + 3, msg_offset - (lea_msg_pos + 7))
    struct.pack_into('<i', code, lea_fail_pos + 3, fail_offset - (lea_fail_pos + 7))

    return bytes(code)


def kill_code():
    """Test kill signal translation: send SIGURG (macOS 16) to self.

    macOS SIGURG=16. Without translation, Linux gets signal 16 = SIGSTKFLT,
    whose default action is "terminate" — process dies.
    With translation, Linux gets signal 23 = SIGURG, whose default action
    is "ignore" — process continues, prints "kill-ok", exits 0.

    Test passes if stdout == "kill-ok\\n" and exit == 0.
    Test fails (no translation) if process dies with signal 16 (returncode -16).
    """
    # Layout:
    #   0x00: mov eax, 0x2000014      (5)   BSD 20 = getpid
    #   0x05: syscall                 (2)   FAST
    #   0x07: mov rdi, rax            (3)   pid = getpid()
    #   0x0a: mov esi, 16             (5)   sig = SIGURG (macOS)
    #   0x0f: mov eax, 0x2000025      (5)   BSD 37 = kill
    #   0x14: syscall                 (2)   SLOW (signal translation)
    #   0x16: mov eax, 0x2000004      (5)   write
    #   0x1b: mov edi, 1              (5)   stdout
    #   0x20: lea rsi, [rip + msg]    (7)   "kill-ok\n"
    #   0x27: mov edx, 8              (5)   len
    #   0x2c: syscall                 (2)   FAST
    #   0x2e: mov eax, 0x2000001      (5)   exit
    #   0x33: mov edi, 0              (5)   code = 0
    #   0x38: syscall                 (2)   SLOW
    #   0x3a: msg "kill-ok\n"         (8)
    msg = b"kill-ok\n"  # 8 bytes
    LEA_END = 0x27
    MSG_OFFSET = 0x3a
    return (
        b'\xb8\x14\x00\x00\x20'                          # mov eax, 0x2000014 (getpid)
        b'\x0f\x05'                                       # syscall (FAST)
        b'\x48\x89\xc7'                                  # mov rdi, rax
        b'\xbe\x10\x00\x00\x00'                          # mov esi, 16 (SIGURG macOS)
        b'\xb8\x25\x00\x00\x20'                          # mov eax, 0x2000025 (kill)
        b'\x0f\x05'                                       # syscall (SLOW)
        b'\xb8\x04\x00\x00\x20'                          # mov eax, 0x2000004 (write)
        b'\xbf\x01\x00\x00\x00'                          # mov edi, 1
        b'\x48\x8d\x35' + struct.pack('<i', MSG_OFFSET - LEA_END) +
        b'\xba\x08\x00\x00\x00'                          # mov edx, 8
        b'\x0f\x05'                                       # syscall (FAST)
        b'\xb8\x01\x00\x00\x20'                          # mov eax, 0x2000001 (exit)
        b'\xbf\x00\x00\x00\x00'                          # mov edi, 0
        b'\x0f\x05'                                       # syscall (SLOW)
        + msg
    )


def madvise_code():
    """Test madvise advice translation: MADV_FREE (macOS 5 → Linux 8).

    First mmap an anonymous page, then call madvise(ptr, 4096, MADV_FREE=5).
    Without translation, Linux sees advice=5 which is invalid (Linux MADV_FREE=8)
    and returns EINVAL. With translation, Linux sees 8 = MADV_FREE and returns 0.

    Test: if madvise returns 0, print "madv-ok\\n" and exit 0.
          if madvise returns nonzero, print "madv-FAIL\\n" and exit 1.
    """
    # Layout (computed dynamically):
    code = bytearray()

    # 0x00: mmap(NULL, 4096, 3, 0x1002, -1, 0)
    code += b'\xb8\xc5\x00\x00\x20'                       # mov eax, 0x20000C5 (mmap)
    code += b'\x31\xff'                                   # xor edi, edi
    code += b'\xbe\x00\x10\x00\x00'                       # mov esi, 0x1000
    code += b'\xba\x03\x00\x00\x00'                       # mov edx, 3
    code += b'\x41\xba\x02\x10\x00\x00'                   # mov r10d, 0x1002
    code += b'\x41\xb8\xff\xff\xff\xff'                   # mov r8d, -1
    code += b'\x45\x31\xc9'                               # xor r9d, r9d
    code += b'\x0f\x05'                                   # syscall (SLOW)
    code += b'\x49\x89\xc7'                               # mov r15, rax (ptr)

    # madvise(ptr, 4096, MADV_FREE=5)
    code += b'\xb8\x4b\x00\x00\x20'                       # mov eax, 0x200004B (madvise, BSD 75)
    code += b'\x4c\x89\xff'                               # mov rdi, r15
    code += b'\xbe\x00\x10\x00\x00'                       # mov esi, 0x1000
    code += b'\xba\x05\x00\x00\x00'                       # mov edx, 5 (MADV_FREE macOS)
    code += b'\x0f\x05'                                   # syscall (SLOW - advice translation)

    # Check result: 0 = success, nonzero = fail
    code += b'\x48\x85\xc0'                               # test rax, rax
    jnz_pos = len(code)
    code += b'\x0f\x85\x00\x00\x00\x00'                   # jnz fail (rel32 placeholder)

    # Success: write "madv-ok\n", exit 0
    code += b'\xb8\x04\x00\x00\x20'                       # mov eax, 0x2000004 (write)
    code += b'\xbf\x01\x00\x00\x00'                       # mov edi, 1
    lea_ok_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'               # lea rsi, [rip+ok_msg]
    code += b'\xba\x08\x00\x00\x00'                       # mov edx, 8
    code += b'\x0f\x05'                                   # syscall (FAST)
    code += b'\xb8\x01\x00\x00\x20'                       # mov eax, 0x2000001 (exit)
    code += b'\xbf\x00\x00\x00\x00'                       # mov edi, 0
    code += b'\x0f\x05'                                   # syscall (SLOW)

    # Fail: write "madv-FAIL\n", exit 1
    fail_path = len(code)
    code += b'\xb8\x04\x00\x00\x20'                       # mov eax, 0x2000004 (write)
    code += b'\xbf\x01\x00\x00\x00'                       # mov edi, 1
    lea_fail_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'               # lea rsi, [rip+fail_msg]
    code += b'\xba\x0a\x00\x00\x00'                       # mov edx, 10
    code += b'\x0f\x05'                                   # syscall (FAST)
    code += b'\xb8\x01\x00\x00\x20'                       # mov eax, 0x2000001 (exit)
    code += b'\xbf\x01\x00\x00\x00'                       # mov edi, 1
    code += b'\x0f\x05'                                   # syscall (SLOW)

    # Data
    ok_msg_offset = len(code)
    code += b"madv-ok\n"     # 8 bytes
    fail_msg_offset = len(code)
    code += b"madv-FAIL\n"   # 10 bytes

    # Patch jnz rel32
    struct.pack_into('<i', code, jnz_pos + 2, fail_path - (jnz_pos + 6))

    # Patch LEA displacements
    struct.pack_into('<i', code, lea_ok_pos + 3, ok_msg_offset - (lea_ok_pos + 7))
    struct.pack_into('<i', code, lea_fail_pos + 3, fail_msg_offset - (lea_fail_pos + 7))

    return bytes(code)


# === Phase 2 constants: dynamic linking load commands ===
LC_LOAD_DYLIB       = 0x0C
LC_DYLD_INFO_ONLY   = 0x80000022
LC_MAIN             = 0x80000028
LC_SYMTAB           = 0x02
LC_DYSYMTAB         = 0x0B


def load_dylib_command(name):
    """Build an LC_LOAD_DYLIB load command.

    Structure: cmd(4) + cmdsize(4) + dylib{name_offset(4), timestamp(4),
    current_version(4), compat_version(4)} + name_string (padded to 8).
    """
    name_bytes = name.encode('ascii') + b'\0'
    padded_len = (len(name_bytes) + 7) & ~7
    name_padded = name_bytes + b'\0' * (padded_len - len(name_bytes))
    cmdsize = 24 + padded_len
    name_offset = 24  # offset from start of load command to name string
    return struct.pack('<IIIIII',
        LC_LOAD_DYLIB, cmdsize,
        name_offset, 0, 0, 0,
    ) + name_padded


def dyld_info_command(rebase_off=0, rebase_size=0, bind_off=0, bind_size=0,
                      lazy_bind_off=0, lazy_bind_size=0):
    """Build an LC_DYLD_INFO_ONLY load command (48 bytes)."""
    return struct.pack('<IIIIIIIIIIII',
        LC_DYLD_INFO_ONLY, 48,
        rebase_off, rebase_size,
        bind_off, bind_size,
        0, 0,  # weak_bind
        lazy_bind_off, lazy_bind_size,  # lazy_bind
        0, 0,  # export
    )


def main_command(entryoff):
    """Build an LC_MAIN load command (24 bytes)."""
    return struct.pack('<IIQQ',
        LC_MAIN, 24,
        entryoff, 0,  # entryoff, stacksize
    )


def symtab_command(symoff, nsyms, stroff, strsize):
    """Build an LC_SYMTAB load command (24 bytes).

    Points to the symbol table (nlist_64 array) and string table,
    both typically in the __LINKEDIT segment.
    """
    return struct.pack('<IIIIII',
        LC_SYMTAB, 24,
        symoff, nsyms,
        stroff, strsize)


def dysymtab_command(indirectsym_off=0, indirectsym_count=0):
    """Build an LC_DYSYMTAB load command (80 bytes).

    Only the indirect symbol table fields are populated; the rest are 0.
    The indirect symbol table maps __la_symbol_ptr / __got entries to
    symbol names via indices into the symbol table.
    """
    return struct.pack('<IIIIIIIIIIIIIIIIIIII',
        LC_DYSYMTAB, 80,
        0, 0,  # ilocalsym, nlocalsym
        0, 0,  # iextdefsym, nextdefsym
        0, 0,  # iundefsym, nundefsym
        0, 0,  # tocoff, ntoc
        0, 0,  # modtaboff, nmodtab
        0, 0,  # extrefsymoff, nextrefsyms
        indirectsym_off, indirectsym_count,  # indirectsymoff, nindirectsyms
        0, 0,  # extreloff, nextrel
        0, 0,  # locreloff, nlocrel
    )


def nlist_64(strx, n_type=0, n_sect=0, n_desc=0, n_value=0):
    """Build a single nlist_64 symbol table entry (16 bytes).

    strx    — index into the string table (offset of the symbol name)
    n_type  — type flags (N_UNDF, N_EXT, etc.)
    n_sect  — section number (1-based) or 0 for NO_SECT
    n_desc  — description flags
    n_value — symbol value (address for defined symbols)
    """
    return struct.pack('<IBBHQ', strx, n_type, n_sect, n_desc, n_value)


def section_64(segname, sectname, addr, size, offset, align=0,
               flags=0, reserved1=0, reserved2=0):
    """Build a section_64 struct (80 bytes).

    Sections are embedded within an LC_SEGMENT_64 load command, after
    the segment_command_64 header. Each section describes a named
    sub-region of the segment (e.g., __text, __got, __la_symbol_ptr).

    Key fields:
      addr     — virtual address (static, before slide)
      size     — size in bytes
      offset   — file offset
      align    — power of 2 alignment
      flags    — section type (low 8 bits) + attributes (high bits)
      reserved1 — indirect symbol table index (for pointer/stub sections)
      reserved2 — stub size (for S_SYMBOL_STUBS)
    """
    seg = segname.encode('ascii').ljust(16, b'\0')[:16]
    sect = sectname.encode('ascii').ljust(16, b'\0')[:16]
    return struct.pack('<16s16sQQIIIIIIII',
        sect, seg,
        addr, size,
        offset,
        align,
        0, 0,   # reloff, nreloc
        flags,
        reserved1, reserved2, 0)  # reserved1, reserved2, reserved3


# Section type constants
S_REGULAR                       = 0x00
S_ZEROFILL                      = 0x01
S_CSTRING_LITERALS              = 0x02
S_NON_LAZY_SYMBOL_POINTERS      = 0x06
S_LAZY_SYMBOL_POINTERS          = 0x07
S_SYMBOL_STUBS                  = 0x08

# Section attributes
S_ATTR_PURE_INSTRUCTIONS        = 0x80000000
S_ATTR_SOME_INSTRUCTIONS        = 0x00000400


# Bind opcode constants (from dyld source)
BIND_OPCODE_DONE                             = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    = 0x40
BIND_OPCODE_SET_TYPE_IMM                     = 0x50
BIND_OPCODE_SET_ADDEND_SLEB                  = 0x60
BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB                    = 0x80
BIND_OPCODE_DO_BIND                          = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

BIND_TYPE_POINTER = 1


def bind_bytecode_for_symbol(symbol_name, ordinal, seg_index, seg_offset):
    """Generate bind bytecode to bind one symbol at a specific location.

    Produces opcodes that tell the loader:
      1. Use dylib with ordinal <ordinal>
      2. Bind symbol <symbol_name>
      3. Type = POINTER (write a 64-bit address)
      4. Target = segment <seg_index> at offset <seg_offset>
      5. Do the bind
      6. Done
    """
    name_bytes = symbol_name.encode('ascii') + b'\0'
    return bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | (ordinal & 0x0F),
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,  # flags=0
    ]) + name_bytes + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | (seg_index & 0x0F),
    ]) + uleb128(seg_offset) + bytes([
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])


def uleb128(value):
    """Encode an unsigned integer as ULEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def hello_dylib_code(code_vmaddr, data_vmaddr):
    """Code for hello_dylib: calls _write(1, msg, 16) via GOT, returns 0.

    This is fundamentally different from raw-syscall test binaries:
    - Raw syscall tests: direct macOS syscalls (mov eax, 0x2000004; syscall)
    - C library tests:  function call (call [rip + got_write])

    The GOT entry is filled by the loader's bind opcode interpreter
    with the address of glibc's write() function. The call goes through
    glibc, which issues a native Linux syscall. Zero translation needed.

    main() is called by the loader (via LC_MAIN) as a C function:
      int main(int argc, char **argv, char **envp, char **apple)
    It returns 0, and the loader calls exit_group(0).
    """
    msg = b"Hello, Mac-ify!\n"  # 16 bytes

    # Code layout (offsets from code start):
    # 0x00: push rbp                    (1)
    # 0x01: mov rbp, rsp               (3)
    # 0x04: mov edi, 1                 (5)  fd = stdout
    # 0x09: lea rsi, [rip + msg_disp]  (7)  buf
    # 0x10: mov edx, 16                (5)  len
    # 0x15: call [rip + got_disp]      (6)  call write() via GOT
    # 0x1b: xor eax, eax              (2)  return 0
    # 0x1d: pop rbp                    (1)
    # 0x1e: ret                        (1)
    # 0x1f: msg "Hello, Mac-ify!\n"   (16)
    # Total: 0x2f = 47 bytes

    lea_end_off  = 0x10
    msg_off      = 0x1f
    call_end_off = 0x1b

    msg_disp = msg_off - lea_end_off                        # 0x0f
    got_disp = data_vmaddr - (code_vmaddr + call_end_off)  # 0xe75

    return (
        b'\x55'                                          # push rbp
        + b'\x48\x89\xe5'                                # mov rbp, rsp
        + b'\xbf\x01\x00\x00\x00'                        # mov edi, 1
        + b'\x48\x8d\x35' + struct.pack('<i', msg_disp)  # lea rsi, [rip+msg]
        + b'\xba\x10\x00\x00\x00'                        # mov edx, 16
        + b'\xff\x15' + struct.pack('<i', got_disp)      # call [rip+got]
        + b'\x31\xc0'                                    # xor eax, eax
        + b'\x5d'                                        # pop rbp
        + b'\xc3'                                        # ret
        + msg
    )


def build_hello_dylib():
    """Build a Mach-O binary that uses dynamic linking:
    - LC_LOAD_DYLIB for libSystem.B.dylib
    - LC_DYLD_INFO_ONLY with bind opcodes for _write
    - LC_MAIN for entry (main is called as a C function)
    - __DATA segment with a GOT entry for _write

    This is the first binary that doesn't use raw syscalls — it calls
    the C library's _write function through the standard GOT mechanism.
    """
    text_vmaddr = 0x1000
    data_vmaddr = 0x2000

    # Build load commands to know their sizes
    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0,
                                  VM_PROT_READ, 0)
    dylib_cmd = load_dylib_command('libSystem.B.dylib')
    dyld_info_size = 48
    main_cmd_size = 24

    # Total load commands: 3 segments + dylib + dyld_info + main
    ncmds = 6
    sizeofcmds = 72 * 3 + len(dylib_cmd) + dyld_info_size + main_cmd_size
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)

    code_vmaddr = text_vmaddr + code_offset
    code = hello_dylib_code(code_vmaddr, data_vmaddr)

    code_end = code_offset + len(code)
    data_fileoff = align_up(code_end, 8)
    data_filesize = 8  # one GOT entry
    bind_off = data_fileoff + data_filesize

    # Bind bytecode: bind _write from ordinal 1 at segment 2 (__DATA), offset 0
    # Segment indices: 0=__PAGEZERO, 1=__TEXT, 2=__DATA
    bind_bc = bind_bytecode_for_symbol('_write', ordinal=1, seg_index=2, seg_offset=0)
    bind_size = len(bind_bc)

    total_size = bind_off + bind_size

    # Build segment commands with final values
    text_seg = segment_command_64(
        '__TEXT', text_vmaddr, align_up(total_size, 0x1000),
        0, code_end,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE)

    data_seg = segment_command_64(
        '__DATA', data_vmaddr, 0x1000,
        data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ | VM_PROT_WRITE)

    dyld_info = dyld_info_command(bind_off=bind_off, bind_size=bind_size)
    main_cmd = main_command(entryoff=code_offset)

    # Assemble
    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=0)
    result = header + pagezero + text_seg + data_seg + dylib_cmd + dyld_info + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += code
    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    result += b'\x00' * data_filesize  # GOT entry (initially 0)
    result += bind_bc

    return result


# === Rebase opcode constants ===
REBASE_OPCODE_DONE                              = 0x00
REBASE_OPCODE_SET_TYPE_IMM                      = 0x10
REBASE_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB  = 0x20
REBASE_OPCODE_DO_REBASE_IMM_TIMES               = 0x50

REBASE_TYPE_POINTER = 1


def rebase_bytecode_for_pointer(seg_index, seg_offset, count=1):
    """Generate rebase bytecode to rebase `count` pointers starting at
    segment `seg_index` offset `seg_offset`."""
    return bytes([
        REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER,
        REBASE_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | (seg_index & 0x0F),
    ]) + uleb128(seg_offset) + bytes([
        REBASE_OPCODE_DO_REBASE_IMM_TIMES | (count & 0x0F),
        REBASE_OPCODE_DONE,
    ])


def build_hello_multi():
    """Build a complex Mach-O binary that tests:
    - 2 dylibs (libSystem.B.dylib + libobjc.A.dylib)
    - Rebase opcodes (internal pointer in __DATA)
    - Non-lazy binds (_exit in __got)
    - Lazy binds (_write, _strlen in __la_symbol_ptr)
    - Stubs (code that jumps through __la_symbol_ptr)

    main() calls strlen(msg) to compute the length, then write(1, msg, len),
    then exit(0). The strlen call tests:
    1. Lazy bind resolution of _strlen (from ordinal 2)
    2. Using a return value from a bound function
    3. Real glibc function interop (strlen is a real C function)

    Layout:
    __TEXT segment (vmaddr 0x1000):
      - __text section: main() code
      - __stubs section: stubs for _write, _strlen (jmp [rip+la_ptr])
      - __cstring section: "Hello, Mac-ify!\\n"
    __DATA segment (vmaddr 0x2000):
      - __got section: _exit (non-lazy bind)
      - __la_symbol_ptr section: _write, _strlen (lazy binds)
      - __data section: internal pointer (rebase target)
    """
    text_vmaddr = 0x1000
    data_vmaddr = 0x2000

    msg = b"Hello, Mac-ify!\n"  # 16 bytes

    # Build load commands to compute sizes
    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0,
                                  VM_PROT_READ, 0)
    dylib1 = load_dylib_command('libSystem.B.dylib')
    dylib2 = load_dylib_command('libobjc.A.dylib')
    dyld_info_size = 48
    main_cmd_size = 24

    ncmds = 7  # 3 segments + 2 dylibs + dyld_info + main
    sizeofcmds = 72 * 3 + len(dylib1) + len(dylib2) + dyld_info_size + main_cmd_size
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)

    # --- __TEXT section layout (file offsets relative to start of __TEXT segment) ---
    # __TEXT.fileoff = 0, so code starts at file offset = code_offset,
    # vmaddr = text_vmaddr + code_offset
    code_vmaddr = text_vmaddr + code_offset

    # main() code:
    #   push rbp; mov rbp, rsp
    #   lea rdi, [rip + msg]           ; arg1 = msg
    #   call strlen_stub               ; call _strlen via stub
    #   mov r15d, eax                  ; save len
    #   mov edi, 1                     ; arg1 = fd = 1 (stdout)
    #   lea rsi, [rip + msg]           ; arg2 = msg
    #   mov edx, r15d                  ; arg3 = len
    #   call write_stub                ; call _write via stub
    #   xor edi, edi                   ; arg1 = exit code = 0
    #   call [rip + got_exit]          ; call _exit via __got (non-lazy)
    #   ; _exit doesn't return, but just in case:
    #   xor eax, eax; pop rbp; ret
    #
    # Stubs (in __stubs section):
    #   write_stub:  jmp [rip + la_write_disp]   ; FF 25 XX XX XX XX (6 bytes)
    #   strlen_stub: jmp [rip + la_strlen_disp]  ; FF 25 XX XX XX XX (6 bytes)

    # Build main code as bytearray for easy patching
    main_code = bytearray()
    main_code += b'\x55'                              # push rbp
    main_code += b'\x48\x89\xe5'                      # mov rbp, rsp
    lea_msg1_pos = len(main_code)
    main_code += b'\x48\x8d\x3d\x00\x00\x00\x00'      # lea rdi, [rip+msg] (placeholder)
    call_strlen_pos = len(main_code)
    main_code += b'\xe8\x00\x00\x00\x00'              # call strlen_stub (placeholder, rel32)
    main_code += b'\x41\x89\xc7'                      # mov r15d, eax (save len)
    main_code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1 (stdout)
    lea_msg2_pos = len(main_code)
    main_code += b'\x48\x8d\x35\x00\x00\x00\x00'      # lea rsi, [rip+msg] (placeholder)
    main_code += b'\x44\x89\xfa'                      # mov edx, r15d (len)
    call_write_pos = len(main_code)
    main_code += b'\xe8\x00\x00\x00\x00'              # call write_stub (placeholder, rel32)
    main_code += b'\x31\xff'                          # xor edi, edi (exit code 0)
    call_exit_pos = len(main_code)
    main_code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit] (placeholder)
    main_code += b'\x31\xc0'                          # xor eax, eax (unreachable)
    main_code += b'\x5d'                              # pop rbp
    main_code += b'\xc3'                              # ret
    main_code_end = len(main_code)

    # Stubs section (after main code)
    stubs_offset = main_code_end
    # Align stubs to 2 bytes (each stub is 6 bytes)
    if stubs_offset % 2: stubs_offset += 1
    while len(main_code) < stubs_offset:
        main_code += b'\xcc'  # int3 padding

    write_stub_offset = len(main_code)
    main_code += b'\xff\x15\x00\x00\x00\x00'          # jmp [rip+la_write] (FF 15 = jmp [rip+disp32]) — actually this is call [rip+disp]. For jmp we want FF 25.
    # Wait — stubs use JMP not CALL. FF 25 = jmp [rip+disp32], FF 15 = call [rip+disp32]
    # Fix: stubs should be jmp
    main_code[write_stub_offset + 1] = 0x25  # change FF 15 to FF 25 (jmp instead of call)

    strlen_stub_offset = len(main_code)
    main_code += b'\xff\x25\x00\x00\x00\x00'          # jmp [rip+la_strlen] (placeholder)

    # __cstring section (after stubs)
    cstring_offset = len(main_code)
    # Align to 1 byte (no alignment needed for strings)
    main_code += msg

    # --- __DATA section layout ---
    # __got: 1 entry (8 bytes) — _exit (non-lazy bind)
    # __la_symbol_ptr: 2 entries (16 bytes) — _write, _strlen (lazy binds)
    # __data: 1 entry (8 bytes) — internal pointer (rebase target)
    got_offset_in_data = 0
    la_write_offset_in_data = 8
    la_strlen_offset_in_data = 16
    data_ptr_offset_in_data = 24

    data_filesize = 32  # 4 entries × 8 bytes
    data_fileoff = align_up(code_offset + len(main_code), 8)

    # Bytecodes
    # Rebase: rebase the internal pointer at __DATA + 24 (points to __cstring msg)
    rebase_bc = rebase_bytecode_for_pointer(
        seg_index=2,  # __DATA is segment index 2 (0=PAGEZERO, 1=TEXT, 2=DATA)
        seg_offset=data_ptr_offset_in_data,
        count=1)

    # Non-lazy bind: _exit from ordinal 1 at __DATA + 0
    bind_bc = bind_bytecode_for_symbol(
        '_exit', ordinal=1, seg_index=2, seg_offset=got_offset_in_data)

    # Lazy binds: _write from ordinal 1 at __DATA + 8, _strlen from ordinal 2 at __DATA + 16
    # Each lazy bind is a separate opcode sequence with its own DO_BIND + DONE
    lazy_bind_bc = bytearray()
    # _write (ordinal 1)
    lazy_bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_write\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(la_write_offset_in_data) + bytes([
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])
    # _strlen (ordinal 2)
    lazy_bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 2,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_strlen\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(la_strlen_offset_in_data) + bytes([
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])

    # File layout: header | code | data | rebase_bc | bind_bc | lazy_bind_bc
    rebase_fileoff = data_fileoff + data_filesize
    bind_fileoff = rebase_fileoff + len(rebase_bc)
    lazy_bind_fileoff = bind_fileoff + len(bind_bc)
    total_size = lazy_bind_fileoff + len(lazy_bind_bc)

    # Build segment commands
    text_seg = segment_command_64(
        '__TEXT', text_vmaddr, align_up(total_size, 0x1000),
        0, code_offset + len(main_code),
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE)

    data_seg = segment_command_64(
        '__DATA', data_vmaddr, 0x1000,
        data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ | VM_PROT_WRITE)

    dyld_info = dyld_info_command(
        rebase_off=rebase_fileoff, rebase_size=len(rebase_bc),
        bind_off=bind_fileoff, bind_size=len(bind_bc),
        lazy_bind_off=lazy_bind_fileoff, lazy_bind_size=len(lazy_bind_bc))

    main_cmd = main_command(entryoff=code_offset)

    # Assemble header + load commands
    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=0)
    result = header + pagezero + text_seg + data_seg + dylib1 + dylib2 + dyld_info + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += main_code

    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    # __DATA contents:
    # __got[0] = 0 (will be filled by bind)
    # __la_symbol_ptr[0] = 0 (will be filled by lazy bind)
    # __la_symbol_ptr[1] = 0 (will be filled by lazy bind)
    # __data[0] = pointer to msg (needs rebase; write the static vmaddr)
    msg_vmaddr = code_vmaddr + cstring_offset
    result += struct.pack('<QQQ', 0, 0, 0)  # got + 2 la_symbol_ptrs (initially 0)
    result += struct.pack('<Q', msg_vmaddr)  # internal pointer (rebase target)

    # Bytecodes
    result += rebase_bc
    result += bind_bc
    result += lazy_bind_bc

    # Now patch the code with computed displacements
    code = bytearray(result[code_offset:code_offset + len(main_code)])

    # Patch lea rdi, [rip+msg] — msg is at cstring_offset in code
    msg_disp_from_lea1 = cstring_offset - (lea_msg1_pos + 7)
    struct.pack_into('<i', code, lea_msg1_pos + 3, msg_disp_from_lea1)

    # Patch lea rsi, [rip+msg]
    msg_disp_from_lea2 = cstring_offset - (lea_msg2_pos + 7)
    struct.pack_into('<i', code, lea_msg2_pos + 3, msg_disp_from_lea2)

    # Patch call strlen_stub (rel32)
    strlen_call_disp = strlen_stub_offset - (call_strlen_pos + 5)
    struct.pack_into('<i', code, call_strlen_pos + 1, strlen_call_disp)

    # Patch call write_stub (rel32)
    write_call_disp = write_stub_offset - (call_write_pos + 5)
    struct.pack_into('<i', code, call_write_pos + 1, write_call_disp)

    # Patch call [rip+got_exit] — __got is at data_vmaddr + 0
    got_exit_vmaddr = data_vmaddr + got_offset_in_data
    got_exit_disp = got_exit_vmaddr - (code_vmaddr + call_exit_pos + 6)
    struct.pack_into('<i', code, call_exit_pos + 2, got_exit_disp)

    # Patch write_stub: jmp [rip+la_write] — __la_symbol_ptr[0] at data_vmaddr + 8
    la_write_vmaddr = data_vmaddr + la_write_offset_in_data
    la_write_disp = la_write_vmaddr - (code_vmaddr + write_stub_offset + 6)
    struct.pack_into('<i', code, write_stub_offset + 2, la_write_disp)

    # Patch strlen_stub: jmp [rip+la_strlen] — __la_symbol_ptr[1] at data_vmaddr + 16
    la_strlen_vmaddr = data_vmaddr + la_strlen_offset_in_data
    la_strlen_disp = la_strlen_vmaddr - (code_vmaddr + strlen_stub_offset + 6)
    struct.pack_into('<i', code, strlen_stub_offset + 2, la_strlen_disp)

    # Write patched code back into result
    result = result[:code_offset] + bytes(code) + result[code_offset + len(main_code):]

    return result


def build_hello_pie():
    """Build a PIE Mach-O binary that tests ASLR/PIE support.

    Sets MH_PIE flag, so the loader randomizes the load address (nonzero slide).
    Contains an internal pointer in __DATA that points to a string in __TEXT.
    The rebase opcode interpreter must add the slide to this pointer.

    main() dereferences the internal pointer to get the string address,
    then calls write(1, *ptr, len). If the rebase correctly applied the slide,
    the pointer is valid and "Hello, Mac-ify!" is printed. If not, the pointer
    points to the static (unmapped) vmaddr → segfault.

    This is the definitive test that ASLR/PIE is working: the rebase must add
    a nonzero, random slide to the internal pointer for the binary to run.
    """
    text_vmaddr = 0x1000
    data_vmaddr = 0x2000

    msg = b"Hello, Mac-ify!\n"  # 16 bytes

    # Build load commands to compute sizes
    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0,
                                  VM_PROT_READ, 0)
    dylib_cmd = load_dylib_command('libSystem.B.dylib')
    dyld_info_size = 48
    main_cmd_size = 24

    ncmds = 6  # 3 segments + dylib + dyld_info + main
    sizeofcmds = 72 * 3 + len(dylib_cmd) + dyld_info_size + main_cmd_size
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)
    code_vmaddr = text_vmaddr + code_offset

    # main() code:
    #   push rbp; mov rbp, rsp
    #   mov rax, [rip + data_ptr_disp]   ; rax = *internal_ptr (rebased with slide)
    #   mov edi, 1                       ; fd = stdout
    #   mov rsi, rax                     ; buf = *ptr (dereferenced)
    #   mov edx, 16                      ; len
    #   call [rip + got_write]           ; call _write via __got
    #   xor edi, edi                     ; exit code = 0
    #   call [rip + got_exit]            ; call _exit via __got
    #   xor eax, eax; pop rbp; ret       ; unreachable
    main_code = bytearray()
    main_code += b'\x55'                              # push rbp
    main_code += b'\x48\x89\xe5'                      # mov rbp, rsp
    mov_rax_pos = len(main_code)
    main_code += b'\x48\x8b\x05\x00\x00\x00\x00'      # mov rax, [rip+data_ptr] (placeholder)
    main_code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    main_code += b'\x48\x89\xc6'                      # mov rsi, rax
    main_code += b'\xba\x10\x00\x00\x00'              # mov edx, 16
    call_write_pos = len(main_code)
    main_code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_write] (placeholder)
    main_code += b'\x31\xff'                          # xor edi, edi
    call_exit_pos = len(main_code)
    main_code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit] (placeholder)
    main_code += b'\x31\xc0'                          # xor eax, eax
    main_code += b'\x5d'                              # pop rbp
    main_code += b'\xc3'                              # ret

    # __cstring section (after main code)
    cstring_offset = len(main_code)
    main_code += msg

    # __DATA layout:
    # __got[0] = _write (non-lazy bind)
    # __got[1] = _exit  (non-lazy bind)
    # __data[0] = internal pointer to msg (needs rebase)
    got_write_offset_in_data = 0
    got_exit_offset_in_data = 8
    data_ptr_offset_in_data = 16
    data_filesize = 24  # 3 entries × 8 bytes
    data_fileoff = align_up(code_offset + len(main_code), 8)

    # Bytecodes
    # Rebase: rebase the internal pointer at __DATA + 16
    rebase_bc = rebase_bytecode_for_pointer(
        seg_index=2, seg_offset=data_ptr_offset_in_data, count=1)

    # Non-lazy binds: _write and _exit from ordinal 1
    bind_bc = bytearray()
    # _write
    bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_write\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_write_offset_in_data) + bytes([
        BIND_OPCODE_DO_BIND,
    ])
    # _exit
    bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_exit\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_exit_offset_in_data) + bytes([
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])

    # File layout: header | code | data | rebase_bc | bind_bc
    rebase_fileoff = data_fileoff + data_filesize
    bind_fileoff = rebase_fileoff + len(rebase_bc)
    total_size = bind_fileoff + len(bind_bc)

    # Build segment commands
    text_seg = segment_command_64(
        '__TEXT', text_vmaddr, align_up(total_size, 0x1000),
        0, code_offset + len(main_code),
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE)

    data_seg = segment_command_64(
        '__DATA', data_vmaddr, 0x1000,
        data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ | VM_PROT_WRITE)

    dyld_info = dyld_info_command(
        rebase_off=rebase_fileoff, rebase_size=len(rebase_bc),
        bind_off=bind_fileoff, bind_size=len(bind_bc))

    main_cmd = main_command(entryoff=code_offset)

    # Assemble header + load commands (MH_PIE flag set!)
    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=MH_PIE)
    result = header + pagezero + text_seg + data_seg + dylib_cmd + dyld_info + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += main_code

    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    # __DATA contents:
    # __got[0] = 0 (will be filled by bind for _write)
    # __got[1] = 0 (will be filled by bind for _exit)
    # __data[0] = pointer to msg (static vmaddr; rebase will add slide)
    msg_static_vmaddr = code_vmaddr + cstring_offset
    result += struct.pack('<QQ', 0, 0)  # two GOT entries (initially 0)
    result += struct.pack('<Q', msg_static_vmaddr)  # internal pointer (rebase target)

    # Bytecodes
    result += rebase_bc
    result += bind_bc

    # Now patch the code with computed displacements
    code = bytearray(result[code_offset:code_offset + len(main_code)])

    # Patch mov rax, [rip+data_ptr] — internal pointer at data_vmaddr + 16
    data_ptr_vmaddr = data_vmaddr + data_ptr_offset_in_data
    data_ptr_disp = data_ptr_vmaddr - (code_vmaddr + mov_rax_pos + 7)
    struct.pack_into('<i', code, mov_rax_pos + 3, data_ptr_disp)

    # Patch call [rip+got_write] — __got[0] at data_vmaddr + 0
    got_write_vmaddr = data_vmaddr + got_write_offset_in_data
    got_write_disp = got_write_vmaddr - (code_vmaddr + call_write_pos + 6)
    struct.pack_into('<i', code, call_write_pos + 2, got_write_disp)

    # Patch call [rip+got_exit] — __got[1] at data_vmaddr + 8
    got_exit_vmaddr = data_vmaddr + got_exit_offset_in_data
    got_exit_disp = got_exit_vmaddr - (code_vmaddr + call_exit_pos + 6)
    struct.pack_into('<i', code, call_exit_pos + 2, got_exit_disp)

    # Write patched code back into result
    result = result[:code_offset] + bytes(code) + result[code_offset + len(main_code):]

    return result


def build_hello_sections():
    """Build a Mach-O binary with proper named sections within segments.

    This is the most realistic test binary: it uses named sections exactly
    like a real macOS binary produced by clang:

    __TEXT segment:
      __text        — main() code (S_REGULAR + S_ATTR_SOME_INSTRUCTIONS)
      __stubs       — lazy stubs (S_SYMBOL_STUBS)
      __cstring     — string literals (S_CSTRING_LITERALS)
    __DATA segment:
      __got         — non-lazy symbol pointers (S_NON_LAZY_SYMBOL_POINTERS)
      __la_symbol_ptr — lazy symbol pointers (S_LAZY_SYMBOL_POINTERS)

    The syscall patcher should ONLY scan __text (code section), not __stubs
    or __cstring. This tests that section-level patching works correctly.

    main() calls strlen(msg) via a lazy stub, then write(1, msg, len) via
    a lazy stub, then exit(0) via __got.
    """
    text_vmaddr = 0x1000
    data_vmaddr = 0x2000

    msg = b"Hello, Mac-ify!\n"  # 16 bytes

    # Build the code first to know its size
    main_code = bytearray()
    main_code += b'\x55'                              # push rbp
    main_code += b'\x48\x89\xe5'                      # mov rbp, rsp
    lea_msg1_pos = len(main_code)
    main_code += b'\x48\x8d\x3d\x00\x00\x00\x00'      # lea rdi, [rip+msg] (placeholder)
    call_strlen_pos = len(main_code)
    main_code += b'\xe8\x00\x00\x00\x00'              # call strlen_stub (placeholder)
    main_code += b'\x41\x89\xc7'                      # mov r15d, eax
    main_code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    lea_msg2_pos = len(main_code)
    main_code += b'\x48\x8d\x35\x00\x00\x00\x00'      # lea rsi, [rip+msg] (placeholder)
    main_code += b'\x44\x89\xfa'                      # mov edx, r15d
    call_write_pos = len(main_code)
    main_code += b'\xe8\x00\x00\x00\x00'              # call write_stub (placeholder)
    main_code += b'\x31\xff'                          # xor edi, edi
    call_exit_pos = len(main_code)
    main_code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit] (placeholder)
    main_code += b'\x31\xc0'                          # xor eax, eax
    main_code += b'\x5d'                              # pop rbp
    main_code += b'\xc3'                              # ret
    text_size = len(main_code)

    # Stubs section (6 bytes each)
    stubs_offset = text_size
    write_stub_offset = stubs_offset
    main_code += b'\xff\x25\x00\x00\x00\x00'          # jmp [rip+la_write] (placeholder)
    strlen_stub_offset = stubs_offset + 6
    main_code += b'\xff\x25\x00\x00\x00\x00'          # jmp [rip+la_strlen] (placeholder)
    stubs_size = 12

    # CString section
    cstring_offset = stubs_offset + stubs_size
    main_code += msg
    cstring_size = len(msg)

    total_text_content = len(main_code)

    # Now build load commands
    # We need to know section addresses and file offsets to build section_64 structs.
    # Sections are part of the LC_SEGMENT_64 load command (after the 72-byte header).

    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0,
                                  VM_PROT_READ, 0)

    # __TEXT segment with 3 sections: __text, __stubs, __cstring
    # Each section_64 is 80 bytes. 3 sections = 240 bytes.
    # LC_SEGMENT_64 cmdsize = 72 + 3*80 = 312 bytes.
    # But we need to know code_offset (where __text starts in the file) to set
    # the section offsets. code_offset = 32 + sizeofcmds, padded to 16.

    # We need sizeofcmds to compute code_offset, but code_offset depends on
    # section sizes within load commands. Let's compute it:
    # Load commands: pagezero(72) + text_seg(72+3*80) + data_seg(72+2*80) +
    #                dylib(48) + dyld_info(48) + main(24) = 792
    dylib_cmd = load_dylib_command('libSystem.B.dylib')
    text_nsects = 3
    data_nsects = 2
    text_seg_cmdsize = 72 + text_nsects * 80  # 312
    data_seg_cmdsize = 72 + data_nsects * 80  # 232

    ncmds = 6
    sizeofcmds = 72 + text_seg_cmdsize + data_seg_cmdsize + len(dylib_cmd) + 48 + 24
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)
    code_vmaddr = text_vmaddr + code_offset

    # Section addresses (static, before slide)
    text_addr = code_vmaddr
    stubs_addr = code_vmaddr + stubs_offset
    cstring_addr = code_vmaddr + cstring_offset

    data_fileoff = align_up(code_offset + total_text_content, 8)
    got_addr = data_vmaddr
    la_symbol_ptr_addr = data_vmaddr + 8  # 2 entries: _exit, then _write+_strlen
    # Actually let's do: __got = _exit (1 entry, 8 bytes)
    #                    __la_symbol_ptr = _write, _strlen (2 entries, 16 bytes)
    data_filesize = 24  # 8 + 16

    # Build section structs
    text_section = section_64('__TEXT', '__text',
        addr=text_addr, size=text_size, offset=code_offset,
        flags=S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS)
    stubs_section = section_64('__TEXT', '__stubs',
        addr=stubs_addr, size=stubs_size, offset=code_offset + stubs_offset,
        align=1, flags=S_SYMBOL_STUBS, reserved1=0, reserved2=6)
    cstring_section = section_64('__TEXT', '__cstring',
        addr=cstring_addr, size=cstring_size, offset=code_offset + cstring_offset,
        align=0, flags=S_CSTRING_LITERALS)
    got_section = section_64('__DATA', '__got',
        addr=got_addr, size=8, offset=data_fileoff,
        align=3, flags=S_NON_LAZY_SYMBOL_POINTERS, reserved1=0)
    la_sym_ptr_section = section_64('__DATA', '__la_symbol_ptr',
        addr=la_symbol_ptr_addr, size=16, offset=data_fileoff + 8,
        align=3, flags=S_LAZY_SYMBOL_POINTERS, reserved1=0)

    # Build segment commands WITH sections
    text_seg = struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, text_seg_cmdsize,
        b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        text_vmaddr, 0x1000,  # vmaddr, vmsize
        0, code_offset + total_text_content,  # fileoff, filesize
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE,
        text_nsects, 0) + text_section + stubs_section + cstring_section

    data_seg = struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, data_seg_cmdsize,
        b'__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        data_vmaddr, 0x1000,
        data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ | VM_PROT_WRITE,
        data_nsects, 0) + got_section + la_sym_ptr_section

    # Bytecodes
    # Non-lazy bind: _exit at __got (ordinal 1)
    bind_bc = bind_bytecode_for_symbol(
        '_exit', ordinal=1, seg_index=2, seg_offset=0)

    # Lazy binds: _write at __la_symbol_ptr[0], _strlen at __la_symbol_ptr[1]
    lazy_bind_bc = bytearray()
    # _write (ordinal 1, __DATA offset 8)
    lazy_bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_write\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(8) + bytes([  # offset 8 in __DATA (la_symbol_ptr[0])
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])
    # _strlen (ordinal 1, __DATA offset 16)
    lazy_bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_strlen\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(16) + bytes([  # offset 16 in __DATA (la_symbol_ptr[1])
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])

    bind_fileoff = data_fileoff + data_filesize
    lazy_bind_fileoff = bind_fileoff + len(bind_bc)
    total_size = lazy_bind_fileoff + len(lazy_bind_bc)

    dyld_info = dyld_info_command(
        bind_off=bind_fileoff, bind_size=len(bind_bc),
        lazy_bind_off=lazy_bind_fileoff, lazy_bind_size=len(lazy_bind_bc))

    main_cmd = main_command(entryoff=code_offset)

    # Assemble
    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=0)
    result = header + pagezero + text_seg + data_seg + dylib_cmd + dyld_info + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += main_code

    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    # __DATA: __got (8 bytes, initially 0) + __la_symbol_ptr (16 bytes, initially 0)
    result += struct.pack('<Q', 0)  # __got[0] = _exit (initially 0)
    result += struct.pack('<QQ', 0, 0)  # __la_symbol_ptr[0,1] (initially 0)

    # Bytecodes
    result += bind_bc
    result += lazy_bind_bc

    # Patch code displacements
    code = bytearray(result[code_offset:code_offset + len(main_code)])

    # lea rdi, [rip+msg] — msg at cstring_offset
    struct.pack_into('<i', code, lea_msg1_pos + 3, cstring_offset - (lea_msg1_pos + 7))
    # lea rsi, [rip+msg]
    struct.pack_into('<i', code, lea_msg2_pos + 3, cstring_offset - (lea_msg2_pos + 7))
    # call strlen_stub
    struct.pack_into('<i', code, call_strlen_pos + 1, strlen_stub_offset - (call_strlen_pos + 5))
    # call write_stub
    struct.pack_into('<i', code, call_write_pos + 1, write_stub_offset - (call_write_pos + 5))
    # call [rip+got_exit] — __got at data_vmaddr
    struct.pack_into('<i', code, call_exit_pos + 2, (data_vmaddr + 0) - (code_vmaddr + call_exit_pos + 6))
    # write_stub: jmp [rip+la_write] — __la_symbol_ptr[0] at data_vmaddr+8
    struct.pack_into('<i', code, write_stub_offset + 2, (data_vmaddr + 8) - (code_vmaddr + write_stub_offset + 6))
    # strlen_stub: jmp [rip+la_strlen] — __la_symbol_ptr[1] at data_vmaddr+16
    struct.pack_into('<i', code, strlen_stub_offset + 2, (data_vmaddr + 16) - (code_vmaddr + strlen_stub_offset + 6))

    result = result[:code_offset] + bytes(code) + result[code_offset + len(main_code):]
    return result


def build_hello_linkedit():
    """Build the most realistic Mach-O binary: everything in __LINKEDIT.

    This binary has the full structure of a real clang-produced binary:
    - 4 segments: __PAGEZERO, __TEXT, __DATA, __LINKEDIT
    - Named sections with proper types and reserved1 indices
    - LC_SYMTAB pointing to symbol table + string table in __LINKEDIT
    - LC_DYSYMTAB pointing to indirect symbol table in __LINKEDIT
    - LC_DYLD_INFO_ONLY with bind/lazy_bind bytecodes in __LINKEDIT
    - Indirect symbol table mapping __got and __la_symbol_ptr entries
      to symbol names via the symbol table

    The loader must:
    1. Map __LINKEDIT segment (read-only)
    2. Parse LC_SYMTAB → symbol table + string table locations
    3. Parse LC_DYSYMTAB → indirect symbol table location
    4. Execute bind bytecodes (from __LINKEDIT) to resolve _exit
    5. Execute lazy bind bytecodes (from __LINKEDIT) to resolve _write, _strlen
    6. Verify indirect symbol table lookup works (reserved1 indices)

    main() calls strlen(msg) + write(1, msg, len) + exit(0) via stubs.
    """
    text_vmaddr = 0x1000
    data_vmaddr = 0x2000
    linkedit_vmaddr = 0x3000

    msg = b"Hello, Mac-ify!\n"  # 16 bytes

    # Build code first
    main_code = bytearray()
    main_code += b'\x55'                              # push rbp
    main_code += b'\x48\x89\xe5'                      # mov rbp, rsp
    lea_msg1_pos = len(main_code)
    main_code += b'\x48\x8d\x3d\x00\x00\x00\x00'      # lea rdi, [rip+msg]
    call_strlen_pos = len(main_code)
    main_code += b'\xe8\x00\x00\x00\x00'              # call strlen_stub
    main_code += b'\x41\x89\xc7'                      # mov r15d, eax
    main_code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    lea_msg2_pos = len(main_code)
    main_code += b'\x48\x8d\x35\x00\x00\x00\x00'      # lea rsi, [rip+msg]
    main_code += b'\x44\x89\xfa'                      # mov edx, r15d
    call_write_pos = len(main_code)
    main_code += b'\xe8\x00\x00\x00\x00'              # call write_stub
    main_code += b'\x31\xff'                          # xor edi, edi
    call_exit_pos = len(main_code)
    main_code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit]
    main_code += b'\x31\xc0'                          # xor eax, eax
    main_code += b'\x5d'                              # pop rbp
    main_code += b'\xc3'                              # ret
    text_size = len(main_code)

    stubs_offset = text_size
    write_stub_offset = stubs_offset
    main_code += b'\xff\x25\x00\x00\x00\x00'          # jmp [rip+la_write]
    strlen_stub_offset = stubs_offset + 6
    main_code += b'\xff\x25\x00\x00\x00\x00'          # jmp [rip+la_strlen]
    stubs_size = 12

    cstring_offset = stubs_offset + stubs_size
    main_code += msg
    cstring_size = len(msg)
    total_text_content = len(main_code)

    # Data layout
    got_offset_in_data = 0    # __got[0] = _exit
    la_write_off = 8          # __la_symbol_ptr[0] = _write
    la_strlen_off = 16        # __la_symbol_ptr[1] = _strlen
    data_filesize = 24
    data_fileoff = align_up(0 + total_text_content, 8)  # relative to TEXT fileoff=0
    # Actually data_fileoff needs to account for code_offset too. Let's compute after.

    # Load command sizes
    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0, VM_PROT_READ, 0)
    dylib_cmd = load_dylib_command('libSystem.B.dylib')

    text_nsects = 3
    data_nsects = 2
    linkedit_nsects = 0
    text_seg_cmdsize = 72 + text_nsects * 80   # 312
    data_seg_cmdsize = 72 + data_nsects * 80   # 232
    linkedit_seg_cmdsize = 72                   # no sections
    dyld_info_size = 48
    symtab_size = 24
    dysymtab_size = 80
    main_size = 24

    ncmds = 8  # 4 segments + dylib + dyld_info + symtab + dysymtab + main - 1 = 8
    # Actually: pagezero + text + data + linkedit + dylib + dyld_info + symtab + dysymtab + main = 9
    ncmds = 9
    sizeofcmds = (72 + text_seg_cmdsize + data_seg_cmdsize + linkedit_seg_cmdsize +
                  len(dylib_cmd) + dyld_info_size + symtab_size + dysymtab_size + main_size)
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)
    code_vmaddr = text_vmaddr + code_offset

    data_fileoff = align_up(code_offset + total_text_content, 8)

    # __LINKEDIT content layout (in file order):
    #   1. bind bytecodes
    #   2. lazy_bind bytecodes
    #   3. indirect symbol table (3 uint32 entries)
    #   4. symbol table (3 nlist_64 entries)
    #   5. string table

    # Build bind bytecodes first (non-lazy: _exit at __got[0])
    bind_bc = bind_bytecode_for_symbol(
        '_exit', ordinal=1, seg_index=2, seg_offset=got_offset_in_data)

    # Lazy binds: _write at la_symbol_ptr[0], _strlen at la_symbol_ptr[1]
    lazy_bind_bc = bytearray()
    lazy_bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_write\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(la_write_off) + bytes([BIND_OPCODE_DO_BIND, BIND_OPCODE_DONE])
    lazy_bind_bc += bytes([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ]) + b'_strlen\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(la_strlen_off) + bytes([BIND_OPCODE_DO_BIND, BIND_OPCODE_DONE])

    linkedit_fileoff = data_fileoff + data_filesize
    bind_fileoff = linkedit_fileoff
    lazy_bind_fileoff = bind_fileoff + len(bind_bc)
    indirectsym_fileoff = lazy_bind_fileoff + len(lazy_bind_bc)

    # Indirect symbol table: 3 entries
    # __got[0] → symtab index 0 (_exit)
    # __la_symbol_ptr[0] → symtab index 1 (_write)
    # __la_symbol_ptr[1] → symtab index 2 (_strlen)
    indirectsym_table = struct.pack('<III', 0, 1, 2)
    indirectsym_count = 3

    symtab_fileoff = indirectsym_fileoff + len(indirectsym_table)

    # String table: "\0_exit\0_write\0_strlen\0"
    strtab = b'\0_exit\0_write\0_strlen\0'
    strtab_fileoff = symtab_fileoff + 3 * 16  # 3 nlist_64 entries

    # Symbol table: 3 entries
    # n_strx: _exit at offset 1, _write at offset 7, _strlen at offset 14
    symtab = (nlist_64(strx=1, n_type=0x01, n_sect=0) +    # _exit (N_EXT | N_UNDF)
              nlist_64(strx=7, n_type=0x01, n_sect=0) +    # _write
              nlist_64(strx=14, n_type=0x01, n_sect=0))    # _strlen

    linkedit_filesize = (strtab_fileoff + len(strtab)) - linkedit_fileoff
    total_size = linkedit_fileoff + linkedit_filesize

    # Build sections with reserved1 indices for indirect sym table
    # __got: reserved1 = 0 (first entry in indirect sym table)
    # __la_symbol_ptr: reserved1 = 1 (entries 1 and 2)
    text_section = section_64('__TEXT', '__text',
        addr=code_vmaddr, size=text_size, offset=code_offset,
        flags=S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS)
    stubs_section = section_64('__TEXT', '__stubs',
        addr=code_vmaddr + stubs_offset, size=stubs_size,
        offset=code_offset + stubs_offset, align=1,
        flags=S_SYMBOL_STUBS, reserved1=0, reserved2=6)
    cstring_section = section_64('__TEXT', '__cstring',
        addr=code_vmaddr + cstring_offset, size=cstring_size,
        offset=code_offset + cstring_offset, flags=S_CSTRING_LITERALS)
    got_section = section_64('__DATA', '__got',
        addr=data_vmaddr, size=8, offset=data_fileoff, align=3,
        flags=S_NON_LAZY_SYMBOL_POINTERS, reserved1=0)
    la_sym_section = section_64('__DATA', '__la_symbol_ptr',
        addr=data_vmaddr + 8, size=16, offset=data_fileoff + 8, align=3,
        flags=S_LAZY_SYMBOL_POINTERS, reserved1=1)

    # Build segment commands
    text_seg = struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, text_seg_cmdsize,
        b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        text_vmaddr, 0x1000, 0, code_offset + total_text_content,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE, text_nsects, 0
    ) + text_section + stubs_section + cstring_section

    data_seg = struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, data_seg_cmdsize,
        b'__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        data_vmaddr, 0x1000, data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
        data_nsects, 0
    ) + got_section + la_sym_section

    linkedit_seg = segment_command_64('__LINKEDIT', linkedit_vmaddr, 0x1000,
        linkedit_fileoff, linkedit_filesize,
        VM_PROT_READ, VM_PROT_READ)

    dyld_info = dyld_info_command(
        bind_off=bind_fileoff, bind_size=len(bind_bc),
        lazy_bind_off=lazy_bind_fileoff, lazy_bind_size=len(lazy_bind_bc))
    symtab_cmd = symtab_command(symtab_fileoff, 3, strtab_fileoff, len(strtab))
    dysymtab_cmd = dysymtab_command(indirectsym_fileoff, indirectsym_count)
    main_cmd = main_command(entryoff=code_offset)

    # Assemble header + load commands
    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=0)
    result = header + pagezero + text_seg + data_seg + linkedit_seg + dylib_cmd + dyld_info + symtab_cmd + dysymtab_cmd + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += main_code

    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    result += struct.pack('<Q', 0)          # __got[0]
    result += struct.pack('<QQ', 0, 0)      # __la_symbol_ptr[0,1]

    # __LINKEDIT contents
    assert len(result) == linkedit_fileoff, f"expected {linkedit_fileoff}, got {len(result)}"
    result += bind_bc
    result += lazy_bind_bc
    result += indirectsym_table
    result += symtab
    result += strtab

    # Patch code displacements
    code = bytearray(result[code_offset:code_offset + len(main_code)])
    struct.pack_into('<i', code, lea_msg1_pos + 3, cstring_offset - (lea_msg1_pos + 7))
    struct.pack_into('<i', code, lea_msg2_pos + 3, cstring_offset - (lea_msg2_pos + 7))
    struct.pack_into('<i', code, call_strlen_pos + 1, strlen_stub_offset - (call_strlen_pos + 5))
    struct.pack_into('<i', code, call_write_pos + 1, write_stub_offset - (call_write_pos + 5))
    struct.pack_into('<i', code, call_exit_pos + 2, (data_vmaddr + 0) - (code_vmaddr + call_exit_pos + 6))
    struct.pack_into('<i', code, write_stub_offset + 2, (data_vmaddr + 8) - (code_vmaddr + write_stub_offset + 6))
    struct.pack_into('<i', code, strlen_stub_offset + 2, (data_vmaddr + 16) - (code_vmaddr + strlen_stub_offset + 6))

    result = result[:code_offset] + bytes(code) + result[code_offset + len(main_code):]
    return result


def build_hello_errno():
    """Build a binary that uses __errno() from the Mac-ify shim.

    This tests that the shim provides macOS-specific functions. The binary:
    1. Calls write(1, msg, 16) to print "Hello, Mac-ify!"
    2. Calls __errno() to get the errno pointer (macOS-specific)
    3. Reads *errno — should be 0 (no error)
    4. If errno == 0, calls write(1, "errno-ok", 8) and exit(0)
    5. If errno != 0, calls write(1, "errno-FAIL", 10) and exit(1)

    __errno() is provided by libmacify_shim.so, NOT by glibc. glibc has
    __errno_location() instead. This proves the shim-first resolution works.
    """
    msg = b"Hello, Mac-ify!\n"  # 16 bytes
    ok_msg = b"errno-ok\n"      # 9 bytes
    fail_msg = b"errno-FAIL\n"  # 10 bytes

    text_vmaddr = 0x1000
    data_vmaddr = 0x2000

    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0, VM_PROT_READ, 0)
    dylib_cmd = load_dylib_command('libSystem.B.dylib')

    ncmds = 6  # 3 segs + dylib + dyld_info + main
    sizeofcmds = 72 * 3 + len(dylib_cmd) + 48 + 24
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)
    code_vmaddr = text_vmaddr + code_offset

    # main() code:
    #   push rbp; mov rbp, rsp
    #   ; write(1, msg, 16)
    #   mov edi, 1
    #   lea rsi, [rip+msg]
    #   mov edx, 16
    #   call [rip+got_write]      ; call _write via GOT
    #   ; errno_ptr = __errno()
    #   call [rip+got_errno]      ; call __errno via GOT
    #   ; if (*errno_ptr == 0) goto ok
    #   cmp dword [rax], 0
    #   jnz fail
    #   ; write(1, "errno-ok", 9)
    #   mov edi, 1
    #   lea rsi, [rip+ok_msg]
    #   mov edx, 9
    #   call [rip+got_write]
    #   xor edi, edi
    #   call [rip+got_exit]
    # fail:
    #   mov edi, 1
    #   lea rsi, [rip+fail_msg]
    #   mov edx, 10
    #   call [rip+got_write]
    #   mov edi, 1
    #   call [rip+got_exit]
    #   ; data
    code = bytearray()
    code += b'\x55'                              # push rbp
    code += b'\x48\x89\xe5'                      # mov rbp, rsp
    # write(1, msg, 16)
    code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    lea_msg_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'      # lea rsi, [rip+msg]
    code += b'\xba\x10\x00\x00\x00'              # mov edx, 16
    call_write1_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_write]
    # errno_ptr = __errno()
    call_errno_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_errno]
    # cmp dword [rax], 0
    code += b'\x83\x38\x00'                      # cmp dword [rax], 0
    jnz_pos = len(code)
    code += b'\x0f\x85\x00\x00\x00\x00'          # jnz fail (rel32 placeholder)
    # ok: write(1, ok_msg, 9)
    code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    lea_ok_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'      # lea rsi, [rip+ok_msg]
    code += b'\xba\x09\x00\x00\x00'              # mov edx, 9
    call_write2_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_write]
    code += b'\x31\xff'                          # xor edi, edi (exit 0)
    call_exit1_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit]
    # fail: write(1, fail_msg, 10)
    fail_offset = len(code)
    code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    lea_fail_pos = len(code)
    code += b'\x48\x8d\x35\x00\x00\x00\x00'      # lea rsi, [rip+fail_msg]
    code += b'\xba\x0a\x00\x00\x00'              # mov edx, 10
    call_write3_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_write]
    code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1 (exit 1)
    call_exit2_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit]
    # data
    msg_offset = len(code)
    code += msg
    ok_msg_offset = len(code)
    code += ok_msg
    fail_msg_offset = len(code)
    code += fail_msg

    # __DATA layout: 3 GOT entries (write, __errno, exit)
    got_write_off = 0
    got_errno_off = 8
    got_exit_off = 16
    data_filesize = 24
    data_fileoff = align_up(code_offset + len(code), 8)

    # Bind bytecodes: _write, __errno, _exit (all from ordinal 1)
    bind_bc = bytearray()
    # _write
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'_write\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_write_off) + bytes([BIND_OPCODE_DO_BIND])
    # __errno — macOS-specific, resolved from shim
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'__errno\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_errno_off) + bytes([BIND_OPCODE_DO_BIND])
    # _exit
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'_exit\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_exit_off) + bytes([BIND_OPCODE_DO_BIND, BIND_OPCODE_DONE])

    bind_fileoff = data_fileoff + data_filesize
    total_size = bind_fileoff + len(bind_bc)

    # Segments
    text_seg = segment_command_64('__TEXT', text_vmaddr, align_up(total_size, 0x1000),
        0, code_offset + len(code),
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE)
    data_seg = segment_command_64('__DATA', data_vmaddr, 0x1000,
        data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE)

    dyld_info = dyld_info_command(bind_off=bind_fileoff, bind_size=len(bind_bc))
    main_cmd = main_command(entryoff=code_offset)

    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=0)
    result = header + pagezero + text_seg + data_seg + dylib_cmd + dyld_info + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += code
    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    result += struct.pack('<QQQ', 0, 0, 0)  # 3 GOT entries
    result += bind_bc

    # Patch displacements
    code = bytearray(result[code_offset:code_offset + len(code)])
    def patch_lea(pos, target):
        struct.pack_into('<i', code, pos + 3, target - (pos + 7))
    def patch_call_indirect(pos, target_vmaddr):
        struct.pack_into('<i', code, pos + 2, target_vmaddr - (code_vmaddr + pos + 6))

    patch_lea(lea_msg_pos, msg_offset)
    patch_lea(lea_ok_pos, ok_msg_offset)
    patch_lea(lea_fail_pos, fail_msg_offset)
    patch_call_indirect(call_write1_pos, data_vmaddr + got_write_off)
    patch_call_indirect(call_errno_pos, data_vmaddr + got_errno_off)
    patch_call_indirect(call_write2_pos, data_vmaddr + got_write_off)
    patch_call_indirect(call_write3_pos, data_vmaddr + got_write_off)
    patch_call_indirect(call_exit1_pos, data_vmaddr + got_exit_off)
    patch_call_indirect(call_exit2_pos, data_vmaddr + got_exit_off)
    # Patch jnz fail
    struct.pack_into('<i', code, jnz_pos + 2, fail_offset - (jnz_pos + 6))

    result = result[:code_offset] + bytes(code) + result[code_offset + len(code):]
    return result


def build_hello_tlv():
    """Build a binary that uses TLV (Thread-Local Variables).

    This tests the full TLV mechanism:
    - __thread_vars section: array of tlv_descriptor structs
    - __thread_data section: initial values for initialized TLVs
    - __thread_bss section: zero-initialized TLVs (size only)
    - _tlv_bootstrap bound via DO_BIND_ULEB_TIMES_SKIPPING_ULEB

    main() accesses a TLV variable, writes "tlv-ok" to stdout, exits 0.
    If TLV is broken, the binary crashes (segfault on NULL storage).
    """
    text_vmaddr = 0x1000
    data_vmaddr = 0x2000

    msg = b"tlv-ok\n"  # 7 bytes

    pagezero = segment_command_64('__PAGEZERO', 0, 0x1000, 0, 0, VM_PROT_READ, 0)
    dylib_cmd = load_dylib_command('libSystem.B.dylib')

    # TLV layout:
    # __thread_vars: 1 tlv_descriptor (24 bytes)
    #   - thunk: initially 0, filled by bind to _tlv_bootstrap
    #   - key: 0
    #   - offset: 0 (offset into per-thread block)
    # __thread_data: 8 bytes (initial value for the TLV: a pointer to msg)
    # __thread_bss: 0 bytes (no zero-initialized TLVs)

    ncmds = 6  # 3 segs + dylib + dyld_info + main
    data_nsects = 3  # __got, __thread_vars, __thread_data
    data_seg_cmdsize = 72 + data_nsects * 80  # 312
    sizeofcmds = 72 * 2 + data_seg_cmdsize + len(dylib_cmd) + 48 + 24
    header_size = 32 + sizeofcmds
    code_offset = align_up(header_size, 16)
    code_vmaddr = text_vmaddr + code_offset

    # main() code:
    #   push rbp; mov rbp, rsp
    #   ; Access TLV: call [tlv_desc.thunk] with rdi = &tlv_desc
    #   lea rdi, [rip + tlv_desc]       ; rdi = &tlv_descriptor
    #   call [rip + got_tlv_bootstrap]  ; call _tlv_bootstrap (via GOT for simplicity)
    #   ; rax = pointer to TLV storage (8 bytes)
    #   ; The TLV storage contains a pointer to msg (initialized from __thread_data)
    #   mov rsi, [rax]                  ; rsi = *tlv_storage = msg pointer
    #   ; write(1, rsi, 7)
    #   mov edi, 1
    #   mov edx, 7
    #   call [rip + got_write]
    #   ; exit(0)
    #   xor edi, edi
    #   call [rip + got_exit]
    code = bytearray()
    code += b'\x55'                              # push rbp
    code += b'\x48\x89\xe5'                      # mov rbp, rsp
    # Access TLV
    lea_desc_pos = len(code)
    code += b'\x48\x8d\x3d\x00\x00\x00\x00'      # lea rdi, [rip+tlv_desc]
    call_tlv_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_tlv_bootstrap]
    # rax = TLV storage ptr
    code += b'\x48\x8b\x30'                      # mov rsi, [rax] (load msg ptr from TLV)
    # write(1, rsi, 7)
    code += b'\xbf\x01\x00\x00\x00'              # mov edi, 1
    code += b'\xba\x07\x00\x00\x00'              # mov edx, 7
    call_write_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_write]
    # exit(0)
    code += b'\x31\xff'                          # xor edi, edi
    call_exit_pos = len(code)
    code += b'\xff\x15\x00\x00\x00\x00'          # call [rip+got_exit]
    code += b'\x5d'                              # pop rbp
    code += b'\xc3'                              # ret
    code_end = len(code)

    # __DATA layout:
    # __got: 3 entries (tlv_bootstrap, write, exit) = 24 bytes
    # __thread_vars: 1 tlv_descriptor = 24 bytes
    # __thread_data: 8 bytes (initial value: pointer to msg)
    got_off = 0
    tlv_desc_off = 24
    thread_data_off = 48
    data_filesize = 56  # 24 + 24 + 8

    # msg goes right after the code (before data section)
    msg_code_offset = len(code)
    code += msg

    # NOW compute data_fileoff (after msg is included in code)
    data_fileoff = align_up(code_offset + len(code), 8)

    # Build TLV descriptor (24 bytes): thunk=0, key=0, offset=0
    tlv_desc = struct.pack('<QQQ', 0, 0, 0)  # thunk, key, offset

    # __thread_data: initial value = pointer to msg
    msg_static_vmaddr = code_vmaddr + msg_code_offset
    thread_data = struct.pack('<Q', msg_static_vmaddr)

    # Bind bytecodes:
    # Non-lazy binds for __got: _tlv_bootstrap (as _tlv_bootstrap), _write, _exit
    # PLUS: DO_BIND_ULEB_TIMES_SKIPPING_ULEB for __thread_vars (bind _tlv_bootstrap to descriptor.thunk)
    bind_bc = bytearray()
    # _tlv_bootstrap → __got[0]
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'_tlv_bootstrap\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_off) + bytes([BIND_OPCODE_DO_BIND])
    # _write → __got[1] (offset 8)
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'_write\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_off + 8) + bytes([BIND_OPCODE_DO_BIND])
    # _exit → __got[2] (offset 16)
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'_exit\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(got_off + 16) + bytes([BIND_OPCODE_DO_BIND])
    # TLV bootstrap: bind _tlv_bootstrap to __thread_vars[0].thunk
    # This uses DO_BIND_ULEB_TIMES_SKIPPING_ULEB: count=1, skip=16 (skip key+offset = 16 bytes)
    bind_bc += bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0]) + b'_tlv_bootstrap\0' + bytes([
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SEGMENT_RELATIVE_OFFSET_ULEB | 2,
    ]) + uleb128(tlv_desc_off) + bytes([
        BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
    ]) + uleb128(1) + uleb128(16) + bytes([  # count=1, skip=16
        BIND_OPCODE_DONE,
    ])

    bind_fileoff = data_fileoff + data_filesize
    total_size = bind_fileoff + len(bind_bc)

    # Segments
    text_seg = segment_command_64('__TEXT', text_vmaddr, align_up(total_size, 0x1000),
        0, code_offset + len(code),
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE)

    # Build __DATA segment WITH sections
    got_addr = data_vmaddr + got_off
    tlv_vars_addr = data_vmaddr + tlv_desc_off
    thread_data_addr = data_vmaddr + thread_data_off

    got_section = section_64('__DATA', '__got',
        addr=got_addr, size=24, offset=data_fileoff + got_off,
        align=3, flags=S_NON_LAZY_SYMBOL_POINTERS, reserved1=0)
    tlv_vars_section = section_64('__DATA', '__thread_vars',
        addr=tlv_vars_addr, size=24, offset=data_fileoff + tlv_desc_off,
        align=3, flags=0x13)  # S_THREAD_LOCAL_VARIABLES
    thread_data_section = section_64('__DATA', '__thread_data',
        addr=thread_data_addr, size=8, offset=data_fileoff + thread_data_off,
        align=3, flags=0x11)  # S_THREAD_LOCAL_REGULAR

    data_seg = struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, data_seg_cmdsize,
        b'__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        data_vmaddr, 0x1000,
        data_fileoff, data_filesize,
        VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
        data_nsects, 0) + got_section + tlv_vars_section + thread_data_section

    dyld_info = dyld_info_command(bind_off=bind_fileoff, bind_size=len(bind_bc))
    main_cmd = main_command(entryoff=code_offset)

    header = mach_header(ncmds=ncmds, sizeofcmds=sizeofcmds, flags=0)
    result = header + pagezero + text_seg + data_seg + dylib_cmd + dyld_info + main_cmd

    # Pad to code_offset
    if len(result) < code_offset:
        result += b'\x90' * (code_offset - len(result))
    result += code
    # Pad to data_fileoff
    if len(result) < data_fileoff:
        result += b'\x00' * (data_fileoff - len(result))
    # __DATA: __got (3 entries) + __thread_vars (1 descriptor) + __thread_data (8 bytes)
    result += struct.pack('<QQQ', 0, 0, 0)  # __got[0,1,2] = 0
    result += tlv_desc                       # __thread_vars[0]
    result += thread_data                    # __thread_data[0] = msg ptr
    result += bind_bc

    # Patch code displacements
    code = bytearray(result[code_offset:code_offset + len(code)])
    def patch_lea(pos, target):
        struct.pack_into('<i', code, pos + 3, target - (pos + 7))
    def patch_call_indirect(pos, target_vmaddr):
        struct.pack_into('<i', code, pos + 2, target_vmaddr - (code_vmaddr + pos + 6))

    # lea rdi, [rip+tlv_desc] — tlv_desc is in __DATA at data_vmaddr + tlv_desc_off
    patch_lea(lea_desc_pos, 0)  # placeholder, will fix below
    struct.pack_into('<i', code, lea_desc_pos + 3,
                     (data_vmaddr + tlv_desc_off) - (code_vmaddr + lea_desc_pos + 7))
    # call [rip+got_tlv_bootstrap] — __got[0] at data_vmaddr + 0
    patch_call_indirect(call_tlv_pos, data_vmaddr + got_off)
    # call [rip+got_write] — __got[1] at data_vmaddr + 8
    patch_call_indirect(call_write_pos, data_vmaddr + got_off + 8)
    # call [rip+got_exit] — __got[2] at data_vmaddr + 16
    patch_call_indirect(call_exit_pos, data_vmaddr + got_off + 16)

    result = result[:code_offset] + bytes(code) + result[code_offset + len(code):]
    return result


TEST_BINARIES = {
    'hello.bin':     hello_code,
    'exit42.bin':    exit42_code,
    'argv.bin':      argv_code,
    'compute.bin':   compute_code,
    'writefile.bin': writefile_code,
    'bench.bin':     bench_code,
    'mmap.bin':      mmap_code,
    'kill.bin':      kill_code,
    'madvise.bin':   madvise_code,
}


def main():
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'tests', 'binaries')
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    for name, fn in TEST_BINARIES.items():
        code = fn()
        macho = build_macho(code)
        path = os.path.join(out_dir, name)
        with open(path, 'wb') as f:
            f.write(macho)
        os.chmod(path, 0o755)
        print(f"  {name:16s}  code={len(code):3d}B  mach-o={len(macho):4d}B  -> {path}")

    # hello_dylib uses a different builder (dynamic linking: LC_LOAD_DYLIB + LC_DYLD_INFO + LC_MAIN)
    macho = build_hello_dylib()
    path = os.path.join(out_dir, 'hello_dylib.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_dylib.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    # hello_multi uses rebases + non-lazy binds + lazy binds + stubs + 2 dylibs
    macho = build_hello_multi()
    path = os.path.join(out_dir, 'hello_multi.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_multi.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    # hello_pie uses MH_PIE flag (ASLR) + rebase with nonzero slide
    macho = build_hello_pie()
    path = os.path.join(out_dir, 'hello_pie.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_pie.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    # hello_sections uses proper named sections (__text, __stubs, __cstring, __got, __la_symbol_ptr)
    macho = build_hello_sections()
    path = os.path.join(out_dir, 'hello_sections.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_sections.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    # hello_linkedit uses __LINKEDIT segment with LC_SYMTAB, LC_DYSYMTAB, indirect sym table
    macho = build_hello_linkedit()
    path = os.path.join(out_dir, 'hello_linkedit.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_linkedit.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    # hello_errno uses __errno() from the Mac-ify shim (macOS-specific function)
    macho = build_hello_errno()
    path = os.path.join(out_dir, 'hello_errno.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_errno.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    # hello_tlv uses TLV (Thread-Local Variables) with __thread_vars/__thread_data sections
    macho = build_hello_tlv()
    path = os.path.join(out_dir, 'hello_tlv.bin')
    with open(path, 'wb') as f:
        f.write(macho)
    os.chmod(path, 0o755)
    print(f"  {'hello_tlv.bin':16s}  mach-o={len(macho):4d}B  -> {path}")

    print(f"\nGenerated {len(TEST_BINARIES) + 7} test binaries in {out_dir}")


if __name__ == '__main__':
    main()
