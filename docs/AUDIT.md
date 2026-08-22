# mac-ify Audit Log (file-by-file)

## src/macify.h
- [BUG/DATA] DYLD_CHAINED_PTR_64_BIND=3 is bogus: real dyld table has no
  "bind" format code. 3=PTR_32 (32-bit entries!) — if ever matched we'd
  mis-decode pointers. Should be deleted; treat unknown formats as fatal.
- [NIT] dyld_chained_fixups_header lacks imports_format; symbols_format
  field actually sits on imports_format's slot (never read -> harmless,
  rename to match Apple for clarity).

## src/fixups.c (first pass read, partial)
- [BUG/LOGIC] ptr_format validation prints "validated: 3 = DYLD_CHAINED_PTR_64_OFFSET"
  but per Apple fixup-chains.h, PTR_64_OFFSET=6, PTR_64=2. Accept set should be
  {2,6} (they share the 64-bit layout) and REJECT others loudly.
- [BUG/SPEC] bind entry decode: ordinal truncated to 16 bits and addend read as
  bits16-31(16 bits). Apple layout: ordinal=24 bits, addend=8 bits (bits24-31).
  Real-world addend>0 breaks us; fix masks to ordinal&0xFFFFFF, addend=(v>>24)&0xFF.
- [NIT] rebase decode reads target as 43 bits (mask 0x7FFFFFFFFFF) + high8<<43;
  Apple: target 36 bits (0-35), high8 bits 36-43, reserved 44-50. Equal when
  high8==0 (every x86_64 userland image), wrong if high8 ever used. Comment/comment
  layout claim in code block above chain walk is stale too.
- [OK] special ordinals 0xFB..0xFF flat treatment matches dyld3 intent.
- [OK] imports parsing assumes DYLD_CHAINED_IMPORT (4-byte) — matches format 1
  table in fixups-cases; we should verify imports_format==1 (don՛t) — note.

## src/segments.c
- [BUG/DATA] strncpy(name, segname, 16) into char[16] buffers for
  segment/section names: Mach-O names fit 16 bytes exactly (e.g.
  "__objc_classname"), so result is non-NUL-terminated; any later %s/snprintf
  read overruns into the next field. Fix: zero-fill dest, strncpy 15.
- [GAP] flat-namespace resolve_symbol loop checks shim/libc but never
  libm_handle (only the ordinal path does). Math symbols for flat-namespace
  binaries can silently miss. Add dlsym(dy->libm_handle, sym) there.

## src/main.c
- [BUG/ROBUST] Non-PIE fallback probe uses MAP_FIXED at min_vmaddr: if any host
  mapping occupies that range it gets silently unmapped/clobbered. Use
  MAP_FIXED_NOREPLACE (Linux 4.17+) and treat EEXIST as "unavailable".
- [GAP] Fat binaries: only FAT_MAGIC (0xCAFEBABE) handled; FAT_MAGIC_64
  (0xCAFEBABF, used by modern universal2 images with 8-byte offsets) rejected.
- [NIT] Stale comment "find close_stream too" in fat-scan loop (copy-paste).
- [OK] LC_UNIXTHREAD count==42 matches x86_THREAD_STATE64 (21 u64 words).
- [OK] PIE slide reservation kept; segments mprotect+memcpy (no MAP_FIXED).
- [OK] Signal stack, crash handler reinstall, PATH setenv ordering.

## src/syscall/flag_translation.c
- [BUG/SAFETY] translate_kill_signal passes through unmapped signals:
  macOS SIGEMT(7) -> returns 7 == Linux SIGBUS! kill(pid,SIGEMT) would
  SIGBUS-kill a process instead of being ignored. Same class: SIGINFO(29)
  -> 29 = Linux SIGLOST-ish (unused but still wrong). Map EMT/INFO to a
  harmless signal (e.g. SIGURG/SIGPROF) or return 0/-1 handled upstream,
  never raw passthrough on collisions.
- [GAP] translate_mmap_flags drops MAP_NORESERVE (macOS 0x40 vs Linux
  0x4000): silently changes memory-commit semantics for mmap users.
- [OK] open flags verified against xnu sys/fcntl.h incl O_NOCTTY 0x20000,
  O_CLOEXEC 0x1000000; right-hand side uses Linux macros correctly.

## src/syscall/patcher.c
- [BUG/SUSPECT] patch_go_systemstack t1 trampoline: t1_jmp_to_pop =
  pop_ret_off - (t1_off + 17 + 5). E9 rel32 target = next_insn(t1_off+17)+rel
  => effective landing = pop_ret - 5 (5 bytes BEFORE 'pop rbp; ret'). t2's
  equivalent math is correct ((i+17)-(t2_off+22)). Either dead path (never
  exercised by tests) or latent Go crash. Needs disassembly verification;
  likely fix: pop_ret_off - (t1_off + 17).
- [OK] backward pattern scan bounds correct incl size_t wrap guard (j==0).
- [OK] fast-path imm rewrite keeps 0x2000000 prefix zeroed correctly.

## src/syscall/sigill_handler.c
- [BUG/SPEC] macOS sigaction flags passed RAW to Linux sigaction. Verified vs
  xnu bsd/sys/signal.h: macOS ONSTACK=0x1/RESTART=0x2/RESETHAND=0x4/
  NOCLDSTOP=0x8/NODEFER=0x10/NOCLDWAIT=0x20/SIGINFO=0x40 vs Linux
  ONSTACK=0x08000000/RESTART=0x10000000/RESETHAND=0x80000000/NOCLDSTOP=1/
  NODEFER=0x40000000/NOCLDWAIT=2/SIGINFO=4. Any app installing a SIGINFO
  handler gets a garbage-flagged kernel registration -> wrong handler ABI.
  Needs explicit flag translation.
- [BUG] sigaction oldact (a3): pointed at static Linux-layout buffer but never
  converted back to macOS layout after the call (sigprocmask/sigaltstack DO
  have post-copy). Apps reading oldact get junk.
- [OK] SIGILL/SEGV/BUS hijack-protection; SS_DISABLE guard; CF convention for Go;
  -errno->-1 conversion; post-translation of oset/oss.
