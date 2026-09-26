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

## shim/presolve.c + shim/io/dl.c (macify_elf_lookup)
- [BUG/CORRECTNESS] macify_elf_lookup treats DT_GNU_HASH as if it were
  DT_HASH: nsyms=hash[1] is only valid for SYSV hash tables. For GNU-hash
  libc, hash[1] = symoffset (first dynamic index), NOT symbol count — the
  fallback cap of 65536 then scans garbage entries past the table end
  until it happens to hit st_value==0. Works by luck today; should use
  gnu_hash bucket walk or bound scan by strtab adjacency.
- [BUG/RACE] find_libc_cb caches libc symtab pointers once; if libc is
  ever dlclosed/reloaded (not our case) stale. Acceptable, document.
- [OK] dlsym passthrough policy avoids NSS deadlock; SC fake handle
  interposition is clean.

## shim/shim_core.c
- [OK] errno translation table matches Apple's sys/errno.h ordering
  (verified spot values 35=EAGAIN, 36=EINPROGRESS, 62=ELOOP).
- [NIT] __progname initialized to "macify-app"; __macify_set_args fixes it
  later — brief window where a constructor could see the placeholder.
- [OK] canary sync from fs:0x28 with nonzero fallback.

## shim/io/dl.c (macify_elf_lookup) — see earlier entry: GNU_HASH misuse.

## shim/io/dl.c — GNU-hash fix applied
- [FIXED] find_libc_cb now computes symbol count correctly for DT_GNU_HASH
  (bloom walk -> max bucket -> chain length) instead of reading hash[1] as
  SYSV nchain. rclone smoke re-verified; one transient exit-139 observed
  once during smoke, unreproducible in 3 consecutive runs + direct runs.
  Watch it.

## shim/io/io_internal.h + flags.c
- [BUG/SPEC][FIXED] MACOS_O_NOCTTY was 0x10000; xnu defines O_NOCTTY=0x20000.
  The userspace open() translator missed every O_NOCTTY request and instead
  matched bit 0x10000 (undefined on macOS). Fixed to 0x20000.
- [OK] All other MACOS_O_* verified against xnu fcntl.h this pass.
- [NIT] Two parallel open-flag translators exist (src/syscall/flag_translation.c
  for slow path vs shim/io/flags.c for symbol path) — drift hazard, both now
  agree; consider unifying later.

## shim/pthread/* (signatures)
- [BUG/SPEC][FIXED] MACOS_PTHREAD_COND_SIG was 0x3CB0B5BB; libpthread's
  pthread_impl.h defines _PTHREAD_COND_SIG_init = 0x3CB0B1BB. Statically
  initialized conditions were never recognized; conversion fell through
  to glibc on a macOS-layout object. Fixed in pthread_internal.h,
  shim.h, tls.c (which also dropped its local #define copies).
- [FIXED] Static-mutex recognition now covers all four initializer
  signatures: normal(ABA7), RECURSIVE(ABA2), ERRORCHECK(ABA1),
  FIRSTFIT(ABA3). Previously only ABA7 + ABA2 (misnamed "SIG_INIT").

## shim/sys/* (skim pass)
- [OK] malloc_zone_* map 1:1 onto glibc allocator; free(zone,ptr) ignores
  zone (fine for the single default zone we emulate).
- [OK] getentropy uses getrandom(2) with /dev/urandom fallback.
- [KNOWN-LIMIT] kqueue/kevent are stubs: changes "succeed", reads return
  0 events. The unconditional logging this section asked for is now gated
  behind MACIFY_TRACE_KQUEUE (docs/Development.md lists it). Measured:
  `ruby -e 'puts 1'` went from 30,579 trace lines on stderr to 0, and still
  emits them with the gate set. Still future work: real kqueue over epoll.

## shim/misc/* (skim)
- [OK] sysctl bounded copies; rune table matches _CTYPE bits; CF stubs
  refcount-consistent on skim.

## scripts/macify-setup-homebrew
- [FIXED] bottle-tag ladder was hardcoded [sonoma,ventura,monterey,all];
  now dynamically prefers the newest darwin tag the API offers
  (sequoia first), falling back to 'all'.

## Audit coverage note (this pass)
Deep-read: macify.h, fixups.c, segments.c, main.c (loader-critical paths),
syscall_table.c (+verified 116 entries vs xnu master), flag_translation.c,
patcher.c, sigill_handler.c, presolve.c, io/dl.c, shim_core.c, net.c
(connect path), dirent.c, pthread sigs, malloc/random/kqueue skims,
setup-homebrew script.
Skimmed/not exhaustively read: shim_mach.c internals, objc_compat.c,
cf.c, sysctl.c, unwind.c, glob.c details, macos_stdio.c details,
libintl.c, watchog.c, tests/real_functional.sh.

## Open issue: brew chain crashes under pure mode ("double free or corruption")
- Repro: macify bash -c 'cd /usr/local && bin/brew --version'
- Chain now fully Mach-O (shebang fix); abort happens inside glibc
  regexec called from a Mach-O frame (bash pattern matching in brew.sh).
- glibc regex_t=64B vs macOS ~72B; layouts differ. Suspect: bash compiled
  regcomp/regexec against macOS ABI assumptions OR heap already corrupted
  earlier by a struct-layout translation gap. Needs dedicated debug session:
  run brew.sh under MALLOC_CHECK_ + catch first corrupting write with
  watchpoints; check which regex call site in bash triggers.
- NOT caused by audit commits 30efd22..b3cf042: crash reproduces at the
  shebang-fix commit too.

## Pure-mode bash regex crash — root cause chain (debug session)

Repro: `macify ~/.macify/bin/bash -c '[[ abc =~ b ]]'` → SIGSEGV/SIGABRT
(rc=134). Isolation results:

- Only SUCCESSFUL matches crash. No-match, empty patterns, `[[ == ]]`
  globs and `case` are clean → corruption is in bash's post-match
  processing, not in regcomp/regexec themselves.
- Shim regex wrapper (misc/regex.c) verified correct end-to-end with
  instrumented runs: real_regcomp/regexec are genuine libc symbols,
  rc=0, pmatch written correctly (so/eo logged sane).
- Locale-independent (C locale + LANG unset both crash). Identical
  crash signature with raw glibc binding (wrapper not involved).
- MALLOC_CHECK_=3 aborts earlier with sysmalloc top-chunk assertion;
  heap chunk walk at fault shows the top header zeroed.
- Faulting instruction: `rep stos %al,(%rdi)` (memset_erms tail) with
  r8 = original dst = a freshly malloc'd ~24-byte bash buffer, rdi =
  exactly the brk limit. Reconstructed initial length from rcx +
  consumed span: **0xFFFFFFFD00000000** (= -3 GiB as signed 64-bit).
- That value is the little-endian packing of two adjacent int32 fields
  **{0, -3}** read as one 64-bit byte count. Our wrapper wrote correct
  {rm_so, rm_eo} into the buffer bash passed us, so the bogus pair
  lives in a DIFFERENT struct that bash's BASH_REMATCH construction
  path treats as a size.

Conclusion: macOS bash 5.3 post-match code builds a 64-bit length from
an adjacent-int32 pair that contains a -3 sentinel where our Linux-side
environment leaves/puts something different than on macOS. Fixing it
requires identifying that struct inside bash (needs source-level debug
build of Homebrew bash or matching bash 5.3 sources) — documented as
the next step. The shim wrapper stays: it fixes the genuine 32-vs-64
byte regex_t overflow for every macOS binary using POSIX regex.

## bash [[ =~ ]] crash — refined mechanism (deterministic)

The successful-match crash is 100% reproducible (6/6 plain runs, 3/3
under gdb) and its bad length correlates exactly with match size:

  [[ abc =~ abc ]]      matched "abc" (3)  → memset len 0xFFFFFFFD_00000000
  [[ "14.5" =~ ^[0-9.]+$ ]] matched "14.5" (4) → memset len 0xFFFFFFFC_00000000

i.e. length = (uint64)(-(int32)match_len) << 32, low word always zero —
the signature of an adjacent int32 pair {0, -match_len} read as a single
size_t. The shim wrapper is exonerated again post-hoc: instrumented
regexec returns correct rc/so/eo and its own malloc probes pass; the
fatal fill starts afterwards in caller code.

Next step: build Homebrew bash 5.3 from source with debug info, break on
the failing call site (memset/memmove entry with rdx = -(len)<<32), walk
the real frame chain, and identify which struct the {0,-match_len} pair
belongs to. Until fixed, any brew code path executing a matching
[[ =~ ]] in shell (utils/os.sh line 89 et al during vendor-install)
remains blocked; non-regex brew operations are unaffected.

## ruby realpath/getcwd emptiness (blocks direct brew.rb invocation)

State after back-translation fix (31deb10): C-level hooks VERIFIED
returning correct virtual paths via MACIFY_TRACE_OPEN — e.g.
realpath("/usr/local/Homebrew/Library/Homebrew/dirtest.rb") returned
the virtual path, getcwd returned "/usr/local" when cwd was in-prefix.
Yet Ruby still observes "" for File.realpath and Dir.pwd (__dir__
degrades to ".", so brew.rb dies at require_relative "global").

The transformation happens inside Ruby between the libc return and the
Ruby value — likely a dev/inode validation pass whose stat view differs
under the loader. Isolation facts collected: File.exist?(host-form)=true,
File.expand_path works, marker-probe proved ruby does NOT route through
the interposed symbol for File.realpath (marker returned untouched).
Next session: determine ruby's actual resolution path (pure-Ruby walk?
direct syscall? alternate symbol), starting from a Homebrew-matching
debug build of the vendored ruby.

Related jail limitation: TCPServer.new(0) crashes under jail (socket
path); Cellar portable-ruby 3.4.5 ships no json parser anywhere
(vendor 4.0.6 is the full one — restored from ghcr blob sha256:ef0bf45e,
verified, boots as VEND-OK 4.0.6).

## [[ =~ ]] FIXED — Darwin regmatch_t ABI mismatch (9518f7c)

Root cause found and fixed. Darwin regex.h: `typedef __off_t regoff_t`
(8B on LP64) → caller regmatch_t entries are {long,long}=16 bytes;
glibc packs {int,int} into 8. Handing bash's pmatch buffer straight to
glibc regexec half-filled each slot; bash re-read the packed pair as
one long and memset -(eo<<32) bytes → sysmalloc assert / SIGSEGV, 100%
deterministic on ANY successful match. Fix: macify_regexec runs glibc
on an intermediate buffer and widens into the caller's 16-byte-stride
layout. Verified: os.sh version check, group captures, no-match path.

brew --version now works end-to-end under the loader (non-jailed):
prints "Homebrew >=4.3.0 (shallow or no git repository)".

Also this session: shim/io/variants.c exports the $DARWIN_EXTSN /
$INODE64 symbol aliases Homebrew-built binaries import (realpath,
fopen, fdopen, select, getgroups + opendir family), routed through
hidden macify_do_* forwarders; must-interpose list extended (c3b5ad4).

## NEW blocker SOLVED: stdout trashing on brew's git-config path

Root cause PROVEN via hardware-watchpoint attach (yama workaround:
shim constructor now honors MACIFY_ALLOW_PTRACE=1 → prctl
PR_SET_PTRACER_ANY) plus elimination:

1. init.c mapped stdout's glibc buffer at fixed 0x10000, so read_ptr
   legitimately held {0x10000-ish, hi=0}.
2. Guest bash's INLINED Darwin putc macro runs `--(fp)->_w`: on glibc
   that decrements read_ptr.HI (offset 0xc) → {bufaddr, -1} poison.
   Fast path then stores chars through _p (= glibc flags → absorbed by
   the 0xfbad2000 safety page → silent output loss).
3. Later glibc internals computed with poisoned pairs and
   _IO_file_overflow wrote them into the write slots (watchpoint caught
   glibc itself at overflow+168 writing {0x10000,-2}); final echo into
   describe-cache/<hash> faulted write(1, 0xffffffff00010000).

Fix (init.c): standards are now setvbuf(_IONBF) and the 0x10000
mapping is disabled — _w starts <= 0 so inline putc always falls into
__swbuf → interposed fputc, keeping glibc fields coherent. Cost:
per-char writes until the macos_sFILE facade replaces the whole
arrangement. Verified: brew --version prints banner non-jailed AND
jailed through bin/brew wrapper; suites 16/16 unit, 27/29 smoke (+2
pre-existing curl), 23/23 real.

Hardening from Oracle review kept regardless: every -1 patch site in
process.c now skips glibc's three standard streams; fix_read_end no
longer propagates a poisoned read_ptr into read_end (resets both to
buf_base instead); all hand-rolled flush sites (crash_handler.c x5,
misc_stubs.c x2, process.c fflush(NULL)) validate pointer sanity via
macify_flush_sane before raw write().

Also learned: guest `kill -STOP $$` arrives as SIGCHLD — Darwin
signal numbers (STOP=17) pass untranslated (Linux 17=SIGCHLD).
Signal translation table needed eventually; worked around with a
file-gated spin for the watchdog.

Remaining for full brew: ruby realpath emptiness (brew list/search
exec cmd/*.rb and die silently at require_relative "global"), jail
socket crash, and long-term the macos_sFILE facade (~25 stdio exports;
note macos_stdio.c's layout comments claim _bf@0x14/0x1c but real
Darwin __sFILE has _bf{base@0x18,size@0x20} — fix before enabling).


## Ground-truth sources landed (kills the "guess to fix" stage)

Fetched upstream sources now live in-tree; every future shim/translation
change must cite one of these, not memory:

- `docs/xnu/headers/` — xnu `bsd/sys/{termios,signal,errno,stat,dirent,
  fcntl,mman,socket,un,ttycom,ioctl,resource,time,event}.h` +
  `i386/signal.h` (main branch).
- `docs/darwin-libc/` — libpthread `pthread_impl.h` (mutex/cond/rwlock/
  once sigs: ABA7/ABA2/ABA1/ABA3, 3CB0B1BB, 2DA8B3B4, 30B1BCBA — shim
  constants verified equal) and Libc `include/_stdio.h` (real __sFILE
  layout: _bf{base@0x18,size@0x20} on LP64 — confirms AUDIT note that
  macos_stdio.c's 0x14/0x1c claim is wrong).
- `docs/dyld/` — dyld `include/mach-o/fixup-chains.h` (PTR_64=2,
  PTR_64_OFFSET=6, ordinal=24b/addend=8b, rebase target=36b/high8=8b)
  and cctools `include/mach-o/loader.h`; `dyld_images.h`.
- `docs/glibc/` — installed 2.44 headers (termios bit/cc/struct/baud
  files, NCCS=32), kernel `asm-generic/termbits.h` (CBAUD=0x100f,
  BOTHER=0x1000, B57600=0x1001…B4000000=0x100f), plus glibc master
  `termios/speed.c`, `sysdeps/unix/sysv/linux/{speed,tcsetattr,
  tcgetattr,cfsetspeed}.c`, `termios_internals.h`, `k_termios.h`.

### Speeds (glibc 2.42 "sane speed_t" rework) — FIXED in shim/io/file.c

glibc ≥2.42: `cfget*` return literal rates; `tcsetattr` walks
c_ispeed/c_ospeed → CBAUD itself (termios2 ioctl). Pre-2.42: user-space
Bxxx = kernel codes (0x1001=B57600 …), cfset* wrote raw CBAUD, tcsetattr
sent TCSETS. Any single-convention table is wrong for one side. Fix:
- read path: decode codes 0..15 + 0x1001..0x100f to rates; pass literal
  rates through (≤15 can't be literal macOS rates — min is B50).
- write path: literal rates into c_ispeed/c_ospeed AND kernel CBAUD
  code into c_cflag (speed_to_cbaud_code); old glibc takes the CBAUD,
  new glibc recomputes CBAUD from literals (___termios2_canonicalize_speeds)
  and overwrites ours — both generations then program the same rate.
- c_line=0 explicitly; macOS OFDEL is 0x20000 (xnu), not 0x100 — the
  oflag table mapped Linux OFDEL (0x80) round-trip into 0x100 (VTDLY!).

### NEW blocker: stdout NUL-flood after SECOND successful regexec (pre-existing)

Repro (deterministic, verified identical at HEAD and with termios changes):
```
macify ~/.macify/bin/bash -c 'echo A; [[ "abc" =~ b ]]; echo B; [[ "xyz" =~ y ]]; echo C'
→ stdout = "A\n" + \0-flood; writes then fail with EAGAIN on a pipe
```
xtrace shows ALL commands execute to completion (rc=0 everywhere) — the
guest is fine; the shim's stdio write path is not. One buffered echo
goes out as a giant write of a zeroed buffer. This is the {0,-len}
adjacent-int32-pair signature from the [[ =~ ]] fix (9518f7c), resurfacing
on a LATER call than the one that fix covers — i.e. a second struct with
the same pair layout (candidates: the regex wrapper's own shim-side
buffer state, or another 2-int field pair adjacent to a size the guest
trusts). The first-match-after-regcomp path is clean; corruption first
appears on a subsequent successful match in the same process.

Classification: GENERAL (POSIX-regex layer, every macOS binary doing
multi-match regex), NOT bash-specific. Next step unchanged from the
[[ =~ ]] session: debug build of Homebrew bash 5.3 + break on the
memset-with-(0,-len<<32) call site; instrument macify_regexec to dump
its caller's pmatch buffer AND the wrapper's own allocator state on
every call to find which struct gets the {0,-len} pair the second time.

Rule going forward: every fix must cite a fetched upstream source and
must generalize — no per-binary patches, ever.

## Go boot flake (T0001) — CLOSED: the shim published its pthread table out of order

Measured rate at a52ed93 is **~30% of runs** (12/40, 9/40 after this
session's commits), not the ~40% the task assumed, and it is far lower
than the 70% an early burst suggested. It is a genuine `rc=139`
SIGSEGV: `sig=11 code=1 adr=0`, faulting `rip=0`, with `m.curg=0`.

### 1. [FIXED] The crash reporter faulted on the very crashes it reports

`src/syscall/crash_handler.c` and `shim/signal/crash_handler.c` both
read guest pointers behind a range check only
(`> 0x10000 && < 0x7fffffffffff`). RIP is **0** on a nil deref, so
`rip_ptr[0..15]` faulted *inside the SIGSEGV handler*: the process died
with no report and no exit path, which is why the flake looked like an
unexplained hang. Now every read is validated against `/proc/self/maps`
(only `r` mappings, parsed once). The shim reporter additionally read
the g from the `g_tls_g_addr` **global**; since
`shim/pthread/create.c` gives each thread its own GS base, that global
is the wrong g on exactly the threads most likely to be crashing. It now
reads the faulting thread's own `gs:0x30` and says which source it used.

### 2. [FIXED] Deferral gate accepted a half-initialised Go runtime

`go_is_ready()` treated any non-NULL `m.gsignal` as "ready". That field
is filled from Go's own heap before a g is scheduled, so it read as
ready while `m.curg` was still NULL, and `sigtrampgo` then dereferenced
NULL. Now `m.curg` (offset **0xb8**, derived from
`docs/golang/runtime2.go-go1.26.4.txt`: g0@0x00, morebuf gobuf@0x08,
divmod@0x38, procid@0x40, gsignal@0x48) must be non-NULL too.

Related and important: a **synchronous** fault must never be deferred.
Returning from a SIGSEGV handler without repairing the fault re-executes
the faulting instruction, so the old "defer everything" path turned a
crash into an unkillable 100%-CPU spin (reproduced; needed a kill -9).
Deferral is now limited to kernel-generated signals (SI_USER, SI_TIMER,
SI_KERNEL, …); a synchronous fault is reported and exits deterministically.

### 3. [FIXED] Go's per-goroutine GS self-test cannot pass under a per-thread GS base

Go re-validates GS in every stack-growth prologue (`runtime.call1024` at
0x100098300, and the call8192 variant):

    mov gs:0x30, 0x123
    mov rax, [rip+..]        ; the GLOBAL tls_g
    cmp rax, 0x123
    je  <ok>
    call <abort>

It passes only when GS base is exactly `tls_g - 0x30`, i.e. when
`gs:0x30` *aliases the global*. macify sets a per-thread GS base so
concurrent Ms do not share one g pointer, so on a worker thread the
compare can never succeed. The assertion's only job is detecting a
platform with no GS, which macify has already satisfied, so the
conditional skip is rewritten to an unconditional one (`je`→`jmp`, same
length, no relocation).

### [CLOSED] Root cause: the shim published its pthread real_* table out of order

The `rip=0` fault is the shim's own pthread wrappers calling a glibc
pointer that was still NULL. It was **not** a GS/signal problem.

`shim/pthread/sync.c` resolved its 16 `real_*` pointers lazily on first
use, gating on a table *member*:

    #define LAZY_INIT() do { if (!real_mutex_lock) init_real_pthread_funcs(); } while (0)

but `init_real_pthread_funcs` stored `real_mutex_lock` **first** and the
entries the wrappers actually call (`real_cond_init`, `real_mutex_init`)
later. A thread entering during that window saw the gate already set,
skipped the init, and called the entry it needed — still NULL — jumping
to 0. The window is wide because each `macify_elf_lookup` linear-scans
~65k libc symbols.

Ground truth from a crash dump (`sig=11 adr=0 code=1 rip=0`):

- the stack top is the guest return address after the `__stubs` call to
  `_pthread_cond_init` (every hop after that call is a tail jump, so no
  shim frame is pushed), and
- `rax = shim_base + 0x8b340`, and `nm build/libmacify_shim.so` puts
  `real_mutex_init` at **0x8b340** (`real_cond_init` at 0x8b310; both in
  `.bss`, zero-initialised).

So `rax` is `&real_mutex_init` and `*(rax) == 0`: the wrapper's
`call *real_mutex_init` is the fault. The `__got` slot the loader filled
(`__DATA_CONST,__got[109]` → shim `pthread_cond_init`) was correct, so
the loader was not at fault.

Proof, A/B on `tests/real/rclone_macos version`:

    unmodified shim                       15/20 crash
    unmodified shim + 100ms init window   20/20 crash
    fixed shim                            20/20 pass
    fixed shim + same 100ms init window   20/20 pass

Measured again in a clean worktree (`git worktree add`, so no other
agent's in-flight edits are in the build): parent `0956388` is 20/20
crash, the fix is 20/20 pass. The injected window makes the race
deterministic; the fix removes it even with the window forced open.

The fix publishes each group through a dedicated flag stored **last**
with release ordering and read with acquire ordering
(`shim/shim.h`: `MACIFY_PUBLISH_LAZY_READY` / `MACIFY_LAZY_INIT`), so no
wrapper can read a pointer before it has been written. Applied to the
three groups whose wrappers call a member with no NULL check:
`shim/pthread/sync.c`, `shim/pthread/attr.c`, `shim/io/flags.c`.
`shim/pthread/tls.c` gates each function on the very pointer it uses,
and the termcap stubs (`shim/shim_core.c`) NULL-check every member, so
neither could NULL-call.

### Superseded: the per-thread GS base survives signal delivery

The earlier note here claimed `gs:0x30` "reads 0 at SIGSEGV delivery"
and pointed at `arch_prctl(ARCH_SET_GS)` vs `wrgsbase`. That is wrong.
A standalone reproducer (set GS base via `arch_prctl` and `wrgsbase`, on
the main and a spawned thread, then deliver SIGSEGV and `raise(SIGUSR1)`,
with and without `SA_ONSTACK`) survives 6/6 cases, and 9/9 macify crash
dumps show `gs:0x30` valid and equal to `g` and `m.g0`. The kernel
snapshots and restores the per-thread GS base correctly; no
`wrgsbase`/`CLONE_SETTLS` change is needed.

## stdout NUL-flood (T0002) — FIXED: was never the regex layer

The task described this as "second successful regexec" emitting a
`{0,-len}` pair. That framing is wrong, and following it would have sent
the next session after the regex wrapper again. Measured facts:

- Trigger is **any second `echo`**, with no regex at all:
  `macify bash -c 'echo A; echo C'` reproduces identically.
- Only when stdout is a **regular file**. Through a pipe the bytes are
  just *lost* (1 byte out instead of 2) — no 4 GiB hole.
- The flood is exactly `A` + `0x100000000` NUL bytes + `C`
  (4294967298 total). Not a {0,-len} pair: a clean 2^32.

### Mechanism (b242ca3)

`strace` showed only two 1-byte writes plus:

    lseek(1, -4294967296, SEEK_CUR)   = -1 EINVAL
    lseek(1, -4294967296, SEEK_CUR)   = -1 EINVAL
    lseek(1,  4294967296, SEEK_CUR)   = 4294967297

so the "giant zeroed write" is really a **4 GiB sparse hole**: the guest
seeks 2^32 past the start and writes `C` there. Backtrace of the seek:
`lseek64 -> _IO_file_sync -> fflush`, i.e. glibc repairing a file offset.

Why the offset was wrong — dumped the guest's stdout at flush time:

    flags=0xfbad2a86  rp=0x7fda8161f603  re=rb=wp=we=bb=be=0x7fdb8161f603

Every pointer agrees except `_IO_read_ptr` (offset 0x08), which is exactly
`0x100000000` low. The low 32 bits are byte-identical to the healthy
value; only the **high** half differs, by one.

That is the whole bug. A macOS binary's putc/getc macros are inlined and
store 32-bit `_r`/`_w` at FILE offsets **0x08/0x10**... precisely, `_w` is
stored at **0x0c**, and glibc's `_IO_read_ptr` occupies 0x08..0x10. So the
guest's `_w` store lands on the **high half** of glibc's read pointer and
decrements it once per character. After enough characters it is 4 GiB
below `_IO_read_base`, and `_IO_file_sync` dutifully seeks by the gap.

The stores are inline in guest text, so they cannot be intercepted. The
fix clamps the read pointers back into range in `macify_fflush`: a stream
with nothing buffered for reading has `read_ptr == read_base`, which is
what `_IO_file_sync` expects. Only the out-of-range direction is touched,
so real reads are unaffected.

Verified:

    bash -c 'echo A; echo C' > f     4294967298 -> 2 bytes
    sed 's/a/X/' < in                0 -> 6 bytes (output was lost entirely)

The second line is the more important one: the same skew was silently
eating all output of any guest whose stdout was a pipe, which no test
had been asserting on.

### Newlines from the `echo` builtin — fixed separately (26c6dd7)

At the time the flood was closed, `echo A; echo C` yielded `AC` — correct
bytes, missing `\n`. That was a **separate defect**, not the flood:

    bash -c 'printf "A\nC\n"'   ->  41 0a 43 0a   (correct)
    bash -c 'echo A; echo C'     ->  41 43         (newlines lost)

`printf` was right, so the guest's escaping and the write path were fine.
It is now fixed, and the cause was the loader's inlined-putc patcher, not
the `echo` builtin: see *bash `echo` loses its trailing newline — RESOLVED*
below for the mechanism. T0002 acceptance criterion 1 (`A\nB\nC\n`
exactly) is **met**.

### Also corrected: macos_sFILE offsets (76a5e25)

`shim/io/macos_stdio.c` declared `_bf` at 0x14/0x1c. Real Darwin
(`docs/darwin-libc/_stdio.h`) puts `__sbuf` at **0x18** — it holds a
pointer, so it is 8-aligned and 4 bytes of padding follow `_file`. This
resolves the open AUDIT note that called the 0x14/0x1c claim wrong. The
struct is currently unreachable (`macify_use_macos_stdio` has no callers),
so this is correctness-only, not a behaviour change.

## bash `echo` loses its trailing newline — RESOLVED (26c6dd7)

Fixed. The cause was the loader's inlined-putc patcher, which the
investigation below had ruled out on the strength of three *configuration*
experiments rather than on whether the patch matched the code that was
actually running.

Darwin's `putc` expands inline (`__sputc`, docs/darwin-libc/_stdio.h:415)
and its fast path stores the character through `_p` (line 417). `_p` is the
first member of `struct __sFILE` (docs/darwin-libc/_stdio.h:133), so it is
FILE offset 0, and on a glibc FILE that is `_flags` (0xfbad2a86). The
shim's own 0xfbad2000 guard-page mapping catches the store, so the byte is
discarded with no libc call and no `write(2)`. That
is precisely the observation this section could not explain: zero hits on
`__swbuf`/`putchar`/`fputc`, correct argument bytes, and no syscall for
the separator or the newline.

gcc emits three shapes of the macro, all from the single expression at
docs/darwin-libc/_stdio.h:416: the `_c != '\n'` term folds away when the
character is a known constant, and each folding leaves a different branch
sequence behind. The patcher only recognised the runtime-char one (`test
_w; jg fast; cmp al,0xa; je slow`), which covered 7 of bash 5.3.15's 30
sites. `echo`'s separator and trailing newline are `putchar(' ')` and
`putchar('\n')` (docs/bash/echo.def:194,199) — the two shapes where the
newline check folds away — so they kept the fast path. `printf` goes through `vfprintf`
and never inlines `putc`, which is why it was always correct.

The three-configuration test below looked like exoneration because every
one of those configurations still left 23 of the 30 sites on the broken
fast path; it only ever toggled the one shape that was already handled.
The fix matches the shared prologue without pinning registers, finds each
site's own slow label, and skips sites whose label is out of rel8 reach or
is not the `__swbuf` character load.

Measured after the fix:

    bash -c 'echo A'             ->  41 0a
    bash -c 'echo A; echo C'     ->  41 0a 43 0a
    bash -c 'echo A B'           ->  41 20 42 0a
    bash -c 'echo -n A'          ->  41

The trace and the ruled-out list below are kept as the record of how the
bug was narrowed — the register trace is what killed the escape/nflag
theories and left the inlined putc macro as the last candidate standing.

### Superseded analysis

### Scope (all verified)

    WORKS   bash printf "A\n"          -> A\n
    WORKS   bash printf "%b" "A\n"     -> A\n
    WORKS   bash echo -e "A\n"         -> A\n
    WORKS   macOS /bin/echo            -> A\n
    WORKS   awk / cut / sed            -> correct
    BROKEN  bash echo A                -> A      (no \n)
    BROKEN  bash echo A B              -> AB     (separator AND newline gone)
    BROKEN  bash echo; echo            -> (nothing at all)
    OK      bash echo -n A             -> A      (-n itself is honoured)

Independent of stdout being a tty, a pipe, or a regular file — verified
all three, including under a pty via `script`.

So this is **not** the T0002 sparse hole (already fixed) and **not** a
general stdio problem: it is specific to the `echo` builtin of *this* bash
build, and it costs only the characters `echo` emits outside `printf("%s")`.

### What the guest actually does (from disassembly of bash 5.3.15)

The builtin is around `0x10006969d`. Per argument it calls the imported
`printf` with the format `"%s"` — confirmed by tracing the shim: two
`printf("%s")` calls for `echo A B`, one per argument. The bytes for the
arguments arrive correctly.

The separator and the trailing newline are emitted separately, and that is
where the output stops:

    0x100069813:  mov  edi,0x20            ; ' '
    0x100069818:  call <PLT __swbuf>       ; emit separator

    0x10006977f:  cmp  DWORD [rbx],0x0    ; rbx = &_terminating_signal
    0x100069782:  je   <skip>             ; NULL -> skip
    0x100069784:  mov  edi,[rbx]
    0x100069786:  call 0x10004d44a        ; emit

`&_terminating_signal` is `0x1000b0ef8`, a `__common` symbol (correctly
zero-initialised; the loader is not at fault — it reads 0 in the file's
terms too, and `__bss`/`__common` are meant to be zero). It is 0 at the
point of the test, so that branch is skipped.

### What has been RULED OUT (so it is not re-chased)

- **Not the putc patch.** Tested in three configurations, all identical
  (`AC`): patch as-is; keep the original `jg` instead of forcing `jmp`;
  and keep the `_w` store instead of NOPing it. The last of these
  disables the patch's effect entirely and still loses the newline, so the
  patch is fully exonerated.
- **Not `__swbuf`/`putchar`/`fputc` binding.** Breakpoints on all three
  (via `dlsym` in the target) record **zero** hits for plain `echo`, while
  the GOT entry for the `__swbuf` stub is confirmed to point at our shim
  and the loader reports `378 resolved, 0 unresolved`.
- **Not a lost libc call.** `strace` shows the `write(1, "A", 1)` and
  `write(1, "C", 1)` and *no* `write` for the newline at all — the byte
  is dropped before the syscall.
- **Not buffering / line-buffering.** Same result on tty, pipe and file.
- **Not locale.** Fails identically under `LC_ALL=C`, and with
  `LC_ALL`/`LANG`/`LC_CTYPE` unset. (The `setlocale` warning about
  `en_US.UTF-8` was present but is not the cause — `printf` is unaffected.
  That warning turned out to be its own defect, fixed separately: see
  *Guest locales* at the end of this file. Guests really did have no
  locale but `C` at the time this section was written.)
- **Not argv.** `printf "<%s>\n" "$@"` round-trips arguments correctly.

### Where to look next (superseded — this was the dead end)

The putc patch was the obvious suspect and was thought to be excluded by
experiment (three configurations, above). It was not, and the reason is
recorded at the top of this section. What remains to be explained is the
central observation:

> Breakpoints on `__swbuf`, `putchar` and `fputc` record **zero** hits
> for plain `echo`, yet the argument bytes come out correctly and the
> separator/newline bytes do not — and `strace` shows no `write` for them
> at all.

So the characters are discarded somewhere that is not a libc call we
interpose and not a `write(2)`. The unexamined space is bash's own
inlined code between the two `printf("%s")` calls and the `__swbuf` call
sites — specifically the branch at `0x1000696b7` (`test r13d,r13d /
je 0x100069758`), which is taken on the normal path and skips straight to
the single-`printf` sequence. `r13` reads 0 at the `printf` breakpoint in
both `echo A` and `echo -n A`, so it is not the `nflag` it was assumed to
be; identifying what actually sets it (and whether the loader leaves it
wrong) is the next concrete step.

### The actual executed path (traced, not inferred)

Reached by breaking on the guest's own PLT stub and single-stepping, so
this is the real instruction stream rather than a guess at the control
flow. `echo A` runs:

    0x10006976e  mov  r12b,0x1
    0x100069771  jmp  0x10006977f
    0x10006977f  cmp  DWORD [rbx],0x0     ; rbx = &_terminating_signal
    0x100069782  je   0x10006978b          ; TAKEN — 0 in &  → skip
    0x10006978b  lea  rax,[rip+0x4775a]   ; 0x1000b0eec
    0x100069792  cmp  DWORD [rax],0x0
    0x100069795  je   0x10006979c
    0x10006979c  test r13d,r13d
    0x10006979f  sete al                 ; al = (r13d == 0)
    0x1000697a2  xor  r12b,0x1            ; r12 low byte -> 0
    0x1000697a6  or   r12b,al             ; r12 low byte -> 1  (al was 1)
    0x1000697a9  jne  0x1000697b3         ; TAKEN
    0x1000697ab  mov  rdi,r15             ; SKIPPED
    0x1000697ae  call <0x10008cfd4>        ; SKIPPED  <-- the emitter
    0x1000697b3  cmp  DWORD [rbp-0x2c],0x0

Observed register values at each step: `r12` goes `...01 -> ...00` at the
`xor`, then back to `...01` at the `or` (because `al`=1), so the `jne` is
always taken and the emit call is always skipped. That is the newline,
gone.

The two things that decide it, and both are wrong in a way worth naming:

1. `&_terminating_signal` (`0x1000b0ef8`, a `__common` symbol) reads 0, so
   the `je` at `0x100069782` is taken. On a real macOS run this is also 0
   at boot, so either that comparison is not the guard we think it is, or
   the register it wants (`rbx`) is not what we believe.
2. `al` is 1, i.e. `r13d == 0`. `r13` is *not* the `nflag`: it reads 0 for
   `echo A` **and** `echo -n A` alike, yet the two must differ somewhere,
   because `-n` is honoured correctly. So `r13` is being loaded from the
   wrong place, and whatever it is meant to carry is not reaching it.

Both point at the same thing: a guest register is not holding the value
the guest's own code put there. That is a *register-state* problem, not a
stdio or symbol-binding problem — which is consistent with every symbol
being correctly resolved (`378 resolved, 0 unresolved`), `__swbuf`/`putchar`
/`fputc` all bound to the shim, and `echo -e`/`printf` (which do not use
this path) working.

### The branch, resolved (register trace)

Single-stepping the real path with `rax` visible:

    s00 0x69771  jmp  -> r12=...01  rax=0x1
    s01 0x6977f  cmp  [rbx],0      (rbx=&_terminating_signal = 0)
    s02 0x69782  je   TAKEN        -> 0x6978b
    s03 0x6978b
    s04 0x69792  cmp  [rax],0      rax=0x...6eec  -> 0
    s05 0x69795  je   TAKEN        -> 0x6979c
    s06 0x6979c  test r13d,r13d
    s07 0x6979f  sete al           al = 1   (r13d == 0)
    s08 0x697a2  xor  r12b,1       r12 -> ...00
    s09 0x697a6  or   r12b,al      r12 -> ...01      <-- re-arms the flag
    s10 0x697a9  jne  TAKEN        -> 0x697b3, skipping 0x697ae
    s11 0x697b3

The call at `0x697ae` — the one that would emit the trailing newline — is
never executed. The reason is line s09: `xor r12b,1` clears the flag and
`or r12b,al` immediately sets it again, because `al` is 1 whenever
`r13d == 0`.

`r13d` is **not** the `nflag`. It is the *escape* flag: `0x100069617:
mov r13d,1` sits inside the `-e` option handler, and the whole option
block is skipped for a plain `echo` (the first argument does not start
with `-`, so `0x100069585: je 0x100069655` jumps over it). Verified:
`r13d == 0` for `echo A` **and** for `echo -n A` — which is correct,
because `-n` is handled by a different variable entirely.

So on a real macOS run the same `r13d == 0` holds and the same
`xor`/`or` pair executes. The difference has to be in `r12` entering this
sequence, not in `r13`. Traced: `r12` is `0x...f10` at `0x6976e` and
`0x...f01` one instruction later, i.e. `mov r12b,0x1` has just run. The
upper bits of `r12` (`0x65fadf00`) are loop-carried garbage, but the
branch only reads the low byte, so that is not it either.

### A caution about the disassembly offsets

The traced addresses above (`0x697xx`) are real — they come from single-
stepping, not from reading the file. But the *static* offsets computed by
adding a guessed file offset to `0x100000000` are not reliable: a loader
hook added late to NOP `and WORD [rax+0x10],0xff9f` at the guessed static
address matched **zero** times, i.e. that byte sequence is not at the
offset the arithmetic implies. Treat file-offset arithmetic on this binary
as unverified; only the single-stepped values should be trusted.

### What this leaves (superseded)

Two further hypotheses were raised and then **disproven by experiment**,
recorded here so they are not retried. Both were true negatives; the real
cause was the half-patched putc macro, not any of these:

- *"`r13` is clobbered between being set and being read."* No. `r13` is
  the *escape* flag; `mov r13d,1` at `0x100069617` lives inside the `-e`
  handler and is correctly skipped for a plain `echo`. `r13d == 0` for
  both `echo A` and `echo -n A`, and that is right.
- *"bash's `and WORD [stdout+0x10],0xff9f` corrupts glibc's
  `_IO_read_end`."* Plausible on paper — macOS has `_flags` at 0x10 where
  glibc has a pointer — but the NOP experiment changed nothing, and the
  pattern did not even occur where predicted.

The control flow is mapped and the skipped emit call identified, but the
reason the flag was set looked unexplained, and no loader-side mechanism
had been shown to cause it — every symbol resolved, no shim function was
entered, and the guest appeared to run a self-consistent instruction
stream.

The lesson worth keeping from this section: "no shim function is entered"
is not evidence that the shim is not involved. An inlined macro that
stores through `_p` never calls the interposed `__swbuf` at all, so the
absence of a hit was the signature of the bug rather than a defence
against it. Note also that the earlier decision to *not* trust
file-offset arithmetic was correct and should stay: the patcher works on
the loaded `__TEXT,__text` section obtained from `find_section`, never on
computed file offsets.

## Guest locales — FIXED (86f2826, then the category swap below)

Two independent defects, both on every guest start. The symptom that led
here was one line of stderr, but the damage was functional: guests had no
locale at all except the built-in `C`.

### 1. The jail had no locale data (86f2826)

`scripts/macify` execs `macify-jail` unless `MACIFY_NO_JAIL` is set, and
the jail ends in `chroot(".")` into the prefix, after which "there is no
host left to reach". The guest runs on the *host's* glibc, so its locale
archive and charset converters are host files at `/usr/lib/locale` and
`/usr/lib/gconv`. Past the chroot those paths resolved inside the prefix,
which holds no locale data, so `setlocale()` failed for every locale but
`C` and bash warned on each start:

    LC_ALL=en_US.UTF-8 macify bash -c true
      -> bash: warning: setlocale: LC_ALL: cannot change locale
         (en_US.UTF-8): No such file or directory

Measured, in this order (each step ruled the next theory in or out):

- host bash with the same environment is silent, so it is not the
  environment or the locale names: the guest's own glibc resolves
  `en_US.UTF-8` fine outside the jail.
- `strace` shows the archive open *succeeding* early in the guest and then
  returning ENOENT later in the same PID — a path that cannot both exist
  and not exist, which is what pointed at the chroot rather than at path
  translation or a missing file.
- `/usr/share/locale/locale.alias` opens successfully in the guest even
  though translation should have sent it to the prefix, which is how the
  glibc-internal opens were separated from the shim's `open` interposer.

Fixed by bind-mounting both directories into the prefix before the chroot,
read-only. Verified: stderr 119 -> 0 bytes, `setlocale(LC_ALL,
"en_US.UTF-8")` returns `en_US.UTF-8` rather than NULL, `locale-archive`
and `C.utf8` visible in the jail, and a write attempt gets `Read-only file
system`.

Ruled out along the way, so it is not retried: the archive is reachable and
maps to its exact length (`mmap(..., 5887328, ...)`), so the data was never
the problem; and a matching exemption added to `macify_translate_path` in
`src/prefix.c` was **inert** — reverting it changed nothing in either jailed
or non-jailed mode, because in jail mode translation is identity anyway. It
was dropped rather than committed.

### 2. macOS and glibc number the locale categories differently

Both platforms number the categories 0..6, so passing a guest's number
straight to glibc silently selects a different one:

| platform | category numbering |
|---|---|
| macOS (docs/darwin-libc/locale.h:45-51) | ALL 0, COLLATE 1, **CTYPE 2**, MONETARY 3, NUMERIC 4, TIME 5, MESSAGES 6 |
| glibc | **CTYPE 0**, NUMERIC 1, **TIME 2**, COLLATE 3, MONETARY 4, MESSAGES 5, ALL 6 |

So a guest calling `setlocale(LC_CTYPE, ...)` set glibc's `LC_TIME`, and
glibc's `LC_CTYPE` stayed on `C`. Every category a guest set landed on the
wrong one. Observed with ruby:

    before:  Encoding.default_external = US-ASCII
             Encoding.locale_charmap   = ANSI_X3.4-1968
             a UTF-8 literal in -e      = SyntaxError: invalid multibyte
                                          character 0xC3
    after:   Encoding.default_external = UTF-8
             Encoding.locale_charmap   = UTF-8
             "ü".bytesize/length        = 2 / 1

The `setlocale(LC_CTYPE, "")` call had returned `en_US.UTF-8` the whole
time, which is what made this look like an `nl_langinfo` bug. A canary
string substituted for the hardcoded `"ANSI_X3.4-1968"` fallback in the
shim's `nl_langinfo` never appeared, proving the ASCII came from glibc
itself and the item translation was fine — the category was the problem.

Fixed by translating the category in `macify_setlocale` before calling
glibc. Verified: `setlocale(cat=2->0, ...)` in the locale trace, ruby
reports UTF-8, and bash stderr stays at 0 bytes on top of fix 1.

### 2b. The extended-locale API had a second, independent renumbering

`setlocale` takes an LC_* *category*; `newlocale` takes an LC_*_MASK *bit*
set, and the bits are numbered differently again — not the same order as the
categories, on either platform:

| | masks |
|---|---|
| macOS (MacOSX SDK `xlocale.h`) | COLLATE 1<<0, CTYPE 1<<1, MESSAGES 1<<2, MONETARY 1<<3, NUMERIC 1<<4, TIME 1<<5, ALL 0x3f |
| glibc (`locale.h`) | CTYPE 1<<0, NUMERIC 1<<1, TIME 1<<2, COLLATE 1<<3, MONETARY 1<<4, MESSAGES 1<<5, ALL every bit |

So a guest's `newlocale(LC_NUMERIC_MASK, ...)` was glibc's LC_MONETARY at the
same bit 0x10 and left numeric on the base locale. `LC_ALL_MASK` is the one
value that coincides (0x3f is also the OR of glibc's six), which is why code
that only ever passed `LC_ALL_MASK` did not notice.

The mask is now translated in `macify_newlocale`, and `uselocale`,
`duplocale` and `freelocale` are interposed as well (they take and return the
opaque `locale_t` that `newlocale` produced, so they only forward).
`freelocale` is shaped to macOS's `int` return even though glibc's returns
`void`.

There was a routing bug underneath this too. A guest that binds these
symbols two-level to libSystem does not reach the shim's plain exports;
`src/segments.c` only honours a `MUST-INTERPOSE` list for ordinal binds. The
five locale entry points were not on it, so even a correct `macify_newlocale`
would have been bypassed. They are now listed there, which also routes
`setlocale` through the shim for two-level-bound guests.

Verified with a new `locale.bin` test binary (`make test`, 17/17): it calls
`newlocale(0x10 /* macOS LC_NUMERIC_MASK */, "tr_TR.UTF-8", NULL)`,
`uselocale`s the result, and checks `localeconv()->decimal_point[0]`:

    translation on:   newlocale(mask=0x10->0x2, ...)  decimal_point ','  -> numeric-ok
    translation off:  (mask 0x10 untranslated)        decimal_point '.'  -> numeric-FAIL

The off run is the discriminating control, so the test cannot pass for the
wrong reason.

### 3. The forced LC_NUMERIC=C is gone, and must not come back

`macify_setlocale` used to call glibc a second time to force
`LC_NUMERIC="C"`, to stop `strtold` looping on a comma decimal point. It was
removed, and its stated purpose could not be reproduced in either direction:

    LC_NUMERIC=tr_TR.UTF-8, sort -n on "2,9"/"2,5"
      with the force:     2,5 2,9
      without the force:  2,5 2,9

Both are the real numeric order, so the force was not what made sort handle
comma decimals, and no loop appeared once it was gone. Mixed input (`1,5`,
`10`, `2`) sorts to `1,5 2 10`. Every other case measured (ASCII and
multibyte input under `C`, `en_US.UTF-8` and `tr_TR`) is identical with and
without it, as are `make test` 16/16 and `make test-real` 23/23.

What the force did do was break `setlocale`'s return value: the second glibc
call overwrote the buffer glibc had just returned from the first, so the
locale name read back as garbage. Visible in the locale trace as
`setlocale(cat=4->1, ...) = <binary junk>`; without the force the same line
returns `tr_TR.UTF-8`.

Correction worth keeping: an earlier commit message on this change said the
force produced a "truncate-at-comma" sort order. It did not. The two runs
above are identical, so the guard should be recorded as removed for the
dangling-pointer bug, not as fixing a reproduced sort or strtold fault.

### 3b. The `unsetenv("LC_CTYPE")` is gone too

`src/runtime.c` used to call `unsetenv("LC_CTYPE")` before entering the
guest, with a comment claiming the shim re-forced `LC_CTYPE=C` afterwards.
It did not, so the call only discarded the user's locale: a guest run with
`LC_CTYPE=de_DE.UTF-8` and no `LC_ALL` fell back to `C`, which is how ruby
reported `US-ASCII`. Removed.

It was not protecting anything. The crash it was added for (sort under a
UTF-8 ctype) is handled by the `0xfbad2000` page mapping and the
`__SEOF`/`__SERR` patcher, and the same failure it supposedly prevented was
already reachable at HEAD through `LANG`/`LC_ALL`, which were never unset:

    HEAD:  LC_CTYPE=en_US.UTF-8  sort -n < file  -> rc=0
    HEAD:  LANG=en_US.UTF-8      sort -n < file  -> rc=2  close failed
    HEAD:  LC_ALL=en_US.UTF-8    sort -n < file  -> rc=2  close failed

Removing it: `make test` 16/16, `make test-real` 23/23, 360 runs of
`sort -n/-rn/-k` across `LC_CTYPE`/`LANG`/`LC_ALL` in `en_US.UTF-8` show no
segfault and no hang, and ruby now reports `UTF-8` under `LC_CTYPE` alone.

### 3c. The "close failed: -: Invalid argument" that exposed it

The `rc=2` above was a real pre-existing defect that mounting the locale
data made reachable. Under a multibyte `LC_CTYPE`, `sort -n` reading a
small *regular file* on stdin failed while the same input from a pipe or a
named file argument passed:

    lseek(0, -32, SEEK_CUR)  = -1 EINVAL   <- glibc _IO_file_sync
    lseek(0, 0, SEEK_CUR)    = 7
    close(0)                 = 0
    write(2, "sort_macos: close failed: -: Invalid argument")

`sort` calls `fflush(stdin)` at exit. glibc's `fflush` on a readable stream
runs `_IO_file_sync`, which seeks by the difference between `_IO_read_ptr`
and `_IO_read_end`; the inlined getc macros leave `_IO_read_end` 32 bytes
past `_IO_read_ptr`, so the sync seeks below the start of the file, fails,
and returns EINVAL. `fclose` was not involved: it returned 0 in a trace
(`macify: fclose(...) = 0`), as did the raw syscall. `macify_fflush`
returned the EINVAL, and `sort` reported it as a close failure.

Fixed in `macify_fflush` (`shim/io/process.c`): on that failure only,
collapse the read buffer (`_IO_read_ptr = _IO_read_end`) so the sync delta
is zero, and retry. Normal buffered reads are untouched — the repair runs
only after glibc has already reported the stream failed. Verified:
`rc=0` and the correct order `2 3 10` for `LC_CTYPE`/`LANG`/`LC_ALL` in
`en_US.UTF-8` and `LC_ALL=tr_TR.UTF-8`; the `DBG` trace showed the corrupt
`d(re-rp)=32` collapsed to `0` on retry.

### 4. A guest hangs when LC_MESSAGES names a locale — FIXED

Mounting the locale data made locales load that previously could not, and
that exposed a hang. With `LANG` and `LC_ALL` unset,
`LC_MESSAGES=tr_TR.UTF-8` hung the guest on the simplest command:

    env -u LANG -u LC_ALL LC_MESSAGES=tr_TR.UTF-8 macify bash -c 'echo hi'
      -> hung (no output, killed by timeout)

`LC_CTYPE`, `LC_NUMERIC`, `LC_COLLATE` and `LC_TIME` set to the same locale
were each fine, and `LC_MESSAGES=en_US.UTF-8` was fine. Before the locale
data was mounted this path was unreachable, because `setlocale` failed for
every locale but `C`.

**Root cause:** a macOS **recursive** mutex converted to a glibc
**non-recursive** one. `convert_macos_mutex` (`shim/pthread/sync.c`)
matched all four macOS static-initializer signatures and overwrote the
mutex with `PTHREAD_MUTEX_INITIALIZER` — the *normal* initializer, kind 0.
bash statically initializes a recursive mutex
(`_PTHREAD_RECURSIVE_MUTEX_SIG_init` = `0x32AAABA2`) and copies it into a
heap struct; the first `pthread_mutex_lock` succeeded, and the recursive
second lock (no intervening unlock) then blocked forever in
`FUTEX_WAIT_PRIVATE` on a lock the thread already owned (`__lock` stuck at
1). The shim's own `MACIFY_TRACE_MUTEX` showed the exact shape:

    pthread_mutex_unlock(0x...0c8) sig=0x1
    pthread_mutex_lock(0x...0c8) sig=0x0
    pthread_mutex_lock(0x...0c8) -> 0
    pthread_mutex_lock(0x...0c8) sig=0x1     <- never returns

**Fix:** map each signature to the matching glibc initializer instead of
collapsing them all to the normal one:

    0x32AAABA7 normal      -> PTHREAD_MUTEX_INITIALIZER             (kind 0)
    0x32AAABA2 recursive   -> PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP (kind 1)
    0x32AAABA1 errorcheck  -> PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP(kind 2)
    0x32AAABA3 firstfit    -> PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP  (kind 3)

**Evidence:**
- `env -u LANG -u LC_ALL LC_MESSAGES=<tr_TR|en_US|C>.UTF-8 macify bash -c 'echo hi'`
  all exit 0 printing `hi` with 0-byte stderr (before: tr_TR hung, rc 124).
- The repro needs the jail: the prefix supplies `.../bash.mo`, which is what
  drives the gettext path; with it the hang is deterministic.
- Host demonstration of the semantics: `PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP`
  has `__kind=1` and a second lock returns 0, while `PTHREAD_MUTEX_INITIALIZER`
  has `__kind=0` and a second lock self-deadlocks.
- Other guests under `LC_MESSAGES=tr_TR.UTF-8` are unaffected: cat, sort,
  sed and grep all rc 0 with correct output.
- `make test` 17/17, `make test-real` 23/23, `make test-smoke` 29/29.

## Guest curl — FIXED (da315ae, 4d90598, 6022289, 84a9fad)

curl in the jail could neither resolve a name nor complete an HTTPS
request: `curl http://example.com` exited 6 ("Could not resolve host"),
`curl https://example.com` exited 27 ("Out of memory", OpenSSL verify
result 14). Three independent defects, each general.

### 1. `linux_to_macos_sockaddr` shifted the payload (da315ae)

The translator built a macOS sockaddr from the Linux one by moving the
whole payload one byte right, to make room for `sa_len`:

    memmove(p + 1, p, addrlen - 1);

But the Linux 2-byte `sa_family` occupies the same two bytes as macOS's
`sa_len` + `sa_family`, so `sin_port`, `sin_addr` and the IPv6 fields
already sit at the same offsets and nothing should move. The shift turned
`sin_port` 0x0035 into 0x0000 and 127.0.0.1 into 53.127.0.0 on every
`recvfrom`/`getsockname`/`getpeername`/`accept` result. c-ares validates a
DNS reply's source against the server it queried, so it discarded every
reply and retried until it gave up.

`strace` showed a valid NODATA HTTPS-RR reply arriving on the socket, so
the failure was above the syscall layer. `curl --trace-config all` showed
the query queued (`[DNS] queueing query [0/1] A example.com:80`) and then
`resolved IPv4: (none)`. Fixed by rewriting only bytes 0 and 1.

### 2. The guest's getaddrinfo bound to glibc (4d90598)

`shim.map` keeps `getaddrinfo`/`freeaddrinfo` local, because exporting
them globally interposes glibc's own calls process-wide and makes the
shim's own `dlopen` fail (`undefined symbol: g_macos_text_lo`). The
consequence was that the guest's imports of those names resolved to
glibc's, not the shim's `macify_*` wrappers, so the macOS-layout rebuild
never ran and curl read glibc's `struct addrinfo`.

macOS and glibc order the two pointer fields oppositely
(`docs/darwin-libc/netdb.h:147`): macOS puts `ai_canonname` at offset 24
and `ai_addr` at 32, glibc the reverse. `socklen_t` is 4 bytes on both, so
only those two fields swap. A macOS binary reading `ai_addr` from offset
32 reads glibc's `ai_canonname`, usually NULL. Fixed in `resolve_symbol`
by routing those two imports to `dlsym(shim, "macify_getaddrinfo")` /
`macify_freeaddrinfo`, with `macify_freeaddrinfo` forwarding non-macOS
callers back to glibc so Linux libraries free their own lists.

### 3. No TLS trust store in the prefix (6022289)

A guest's `/etc/ssl/cert.pem` resolves into the prefix, and curl uses that
path as its default CAfile. Nothing created it, so OpenSSL found no trust
anchors and every HTTPS verification failed with verify result 14. Fixed
in `macify_init_prefix`: copy the first existing host CA bundle to
`<prefix>/etc/ssl/cert.pem`, refreshing when the host bundle is newer.
`MACIFY_TRACE_OPEN` had shown `fopen("/etc/ssl/cert.pem", "r") = (nil)
errno=2` before the fix.

A/B that isolates it: with `<prefix>/etc/ssl` made a regular file so
provisioning cannot write, HTTPS exits 27; with it writable the same
command exits 0 and returns the page.

### Ruled out, so it is not retried

- A DNS-reply source rewrite (`unredirect_dns_source`, presenting the real
  resolver's reply as coming from 127.0.0.1:53) was written, then removed.
  With the sockaddr fix in place, HTTP and HTTPS both pass without it, so
  it was not load-bearing.
- A prefix `/etc/hosts` entry for example.com was used as a scaffold
  during diagnosis and removed. The host `/etc/hosts` has no such entry,
  so the passing runs resolve through the resolver, not the hosts file.
- The `dns_configuration_copy()` NULL return (c-ares then falls back to
  127.0.0.1:53, which `macify_connect` redirects) is a real quirk but not
  the cause: the redirect works once the reply's sockaddr is not
  corrupted.

## Guest stdio corruption from inlined getc — FIXED (ea82454, 4529e01)

`make test-functional` failed on `cut -d' '` (stdout mismatch), and the
output varied between runs: `printf 'hello\nworld\n' | macify cut -c1`
printed only `h`, and field mode wrote a stream of NULs. Reproduced in
about half of runs. `sed` on stdin failed outright with `read error on
stdin: Invalid or incomplete multibyte or wide character` (exit 4), and
`strings` dropped its output in about half of runs or, once its macro
was patched but not all of it, hung printing `h`.

`paste` was listed alongside `cut` in the original report but does not
reproduce: it exits 0 with correct output on both the unmodified and the
fixed tree, reading files and stdin alike. It is not evidence here.

### Mechanism

`cut` reads with the Darwin `getc` macro inlined:

    --(p)->_r < 0 ? __srget(p) : (int)(*(p)->_p++)

`__stdinp` holds glibc's `stdin` (the shim constructor sets it, and
`macify_use_macos_stdio` switches only stdout/stderr), so `_r` (offset
8) is the low half of glibc's `_IO_read_ptr` and `_p` (offset 0) is
glibc's `_flags` (0xfbad2084). When `_IO_read_ptr`'s low 32 bits are
large, `--_r` stays non-negative and the fast path dereferences
`0xfbad2084` and stores `_p + 1` back, so each call reads the next byte
of the guard page and advances `_p` until it leaves the page at
0xfbad3000 and faults. Which branch runs depends on the stdio buffer
address, hence the flake.

The shim's defense is to set `_r = -1` after a read so the next call
takes the slow path, but `macify_is_glibc_standard` skips that for the
three standard streams, because poisoning `_IO_read_ptr` breaks glibc's
own fread/underflow. The other defense, the loader's getc-macro rewrite
(NOP the `--_r` store, change the `jle` to an unconditional `jmp` to
`__srget`), was gated on the binary also testing the FILE EOF/ERR bits
(`test [fp+0x10], 0x20/0x40`). `cut` has the getc macro but checks end
of input from `getc`'s return value, so the count was 0 and the macro
was left alone.

### Fix 1 (ea82454) — patch the getc macro on its own

Patch the getc macro whenever its instruction shape is present, not only
when an EOF check is also present, and set `macify_getc_patched` when any
site was rewritten. `cut -c1` now prints `h` and `w` in 10 of 10 runs;
`cut -d' ' -f1` on a three-line file prints `b`, `a`, `c` in 20 of 20.

### Fix 2 (4529e01) — every encoding, and the EOF gate

Fix 1 kept the matcher's original single encoding: `lea ecx,[rax-1]`
(`8d 48 ff`), `test eax,eax`, a short `jle`. Compilers use others, and
every missed site keeps its `--_r` store:

| binary / site | encoding the matcher missed |
|---|---|
| `strings` `_get_char` | `lea edx,[rax-1]`, base `%r12` (`8d 50 ff`, REX.B + SIB) |
| `sed` `_last_file_with_data_p`, `cut` `_cut_fields` (2) | inverted `jg` (`7f`), or near `jle` (`0f 8e`) |

In `strings` the missed `--_r` store decremented `_IO_read_ptr` between
calls, so glibc `fgetc` returned the same `h` forever and the program
looped; in `sed` the store plus the unpatched `_inchar` EOF check gave
the multibyte error. The matcher is now a small x86-64 decoder
(`dec_getc_op`) that accepts the whole cluster with any registers —
REX and SIB, short or near, `jle` or the inverted `jg` — and checks the
register identities (`load.reg == lea.base == test.reg`,
`lea.reg == store.reg`, `load.base == store.base`). Match counts rose
from 3→4 (`sed`), 1→2 (`strings`), 5→7 (`cut`), 5→6 (`tar`), 12→13
(`pr`), 0→1 (`expand`, `od`, `nano`, `unexpand`); the added `cut` and
`strings` sites were confirmed to be genuine inlined macros by
disassembly.

The `__SEOF/__SERR` rewrite (force the no-EOF/no-error path) no longer
keys on `__text` size. That guard came from a `strings` hang, but
`strings` has **no** EOF-check sites — the hang was the missing getc
site above. `sed` *needs* the rewrite and is above 100KB, so the size
gate made it unfixable. The rewrite now runs when a getc macro was
patched (the case it exists for) or when the binary is small, as
before. `bash` (0 getc macros, 565 KB) and every other fread/fgets
binary are unchanged.

### Evidence

- `sed`: `echo hello | macify tests/real/sed_macos 's/hello/goodbye/'`
  → `goodbye`, exit 0, 20/20 (before: 0/20, exit 4). Multibyte input
  works (`printf 'h\xc3\xa9llo\n' | … 's/h\xc3\xa9llo/bonjour/'` →
  `bonjour`), as do `sed -n '2p' file` and chained `-e`.
- `strings`: `echo 'hello world' | macify strings_macos` → `hello world`,
  10/10 (before: `hello world` or empty, ~50/50).
- `cut -d: -f2` 10/10; `paste`, `expand`, `od -c`, `diff`, `du`, and a
  `tar -cf` / `tar -tf` round-trip all correct.
- `make test` 17/17, `make test-real` 23/23, `make test-smoke` 29/29.
- `make test-functional` 101 pass / 1 fail / 2 skip, against the
  unmodified tree's 100 / 1 / 3; the only failure is `less` (no
  terminfo), which fails identically before.
- A/B on the `cut` flake: the unmodified tree prints `h` in about half
  of runs, the fixed tree in 10 of 10.
- Scanning every `__text` adds ~12 ms on `starship` (8.5 MB) and
  ~107 ms on `rclone` (36 MB).

### Adjacent, not fixed here

- `less` fails with `'xterm': unknown terminal type`; the prefix has no
  `<prefix>/usr/share/terminfo`.

## Threaded guests hang on glibc's compat pthread_cond symbols — FIXED

`pigz -p2 -c` wrote the 22-byte gzip header and then hung; `strace` showed
the main thread spinning on `FUTEX_WAKE` with no waiter while workers sat
in `FUTEX_WAIT`. The cond was not a lost wakeup: every
`pthread_cond_wait` returned 0 immediately (254,207 times in one run)
because the condvar was corrupt.

The shim resolves real glibc functions by walking libc's dynamic symbol
table in `macify_elf_lookup` (`shim/io/dl.c`) and returning the **first**
name match. glibc exports several pthread functions under two versions,
and the stale `@GLIBC_2.2.5` compat entry is listed **before** the default
`@@GLIBC_2.3.2` one:

| symbol | `@GLIBC_2.2.5` (returned) | `@@GLIBC_2.3.2` (default) |
|---|---|---|
| `pthread_cond_init` | 28 B: `movq $0,(%rdi)` — zeroes only `__wseq` | 51 B: three `movups` — zeroes all 48 B |
| `pthread_cond_wait` | 148 B compat | 408 B |
| `pthread_cond_signal` | 115 B compat | 662 B |
| `pthread_cond_broadcast` | 115 B compat | 689 B |

The old `pthread_cond_init` assumes its argument already came from
`PTHREAD_COND_INITIALIZER` (all-zero) and only resets `__wseq`; for a
`malloc`'d job struct it leaves `__g_refs`/`__g_size`/`__g1_orig_size`/
`__wrefs`/`__g_signals` holding stale heap garbage (confirmed: a shim dump
at `wait#0` showed `__wseq=0` but pointer-shaped values at offsets 8–47,
present before the first wait). glibc's condvar then miscomputes the
waiter group and returns without blocking.

Fix: `macify_elf_lookup` now parses `DT_VERSYM` and prefers the
**default** version (`VERSYM_HIDDEN` clear), falling back to a hidden one
only when no default exists. It also skips `STT_GNU_IFUNC` entries, whose
`st_value` is a resolver rather than the implementation, so an IFUNC
default can never be returned as a callable address (it falls through to
`real_dlsym`, which runs the resolver). This is a general fix for every
versioned symbol the shim resolves — the same ordering affects `memcpy`,
`glob`, `dlopen`, the C11 `cnd_*` family, and others.

### Evidence

- `pigz -p{1,2,3,4,8} -c /tmp/pigz_in.bin` (3 MB) all exit 0 and
  `gzip -dc` reproduces the input byte-for-byte; `-p3 -d` round-trips a
  host `gzip` file. Before the fix, `-p1` worked but `-p2+` hung (rc 124).
- A shim dump of the cond right after `pthread_cond_init` showed all 48
  bytes zero after the fix, versus only the first 8 before.
- `make test` 17/17, `make test-real` 23/23, `make test-smoke` 29/29,
  `make test-functional` 102 pass / 1 fail / 1 skip (only the pre-existing
  `less` failure; `pigz -c` now passes instead of being skipped).

## Host-path guest binaries under the jail — FIXED (144cc48)

`scripts/macify <guest> [args]` runs the loader through `macify-jail`
(`scripts/macify:135`, `:189-193`), which unshares a mount and user
namespace and chroots into the prefix. A guest named by **host path** did
not exist for the loader at all: `load_file` (`src/segments.c:592-594`)
opened the path inside the new root, where it is not, and printed the
bare `open: No such file or directory`. Prefix-internal paths (`macify
shell`, `/usr/local/bin/bash`) were unaffected, which is why the suites
stayed green while the documented CLI form did not work.

`src/jail.c` now resolves the guest path before anything chdirs
(`guest_path_index` `:91`, the resolve block `:299-327`) and, when it
lies outside the prefix, mounts that one file read-only at the same
absolute path under the prefix and rewrites the loader's argv slot to
the resolved path. The mount is the locale-mount shape (`mirror_host_file`
`:156-172`, precedent at `:405-427`): `MS_BIND`, then
`MS_BIND|MS_REMOUNT|MS_RDONLY`. It is one file: no directory, no sibling
dylibs, and the paths named in the guest's arguments are untouched, so a
host file the guest is asked to read stays invisible. A real prefix file
at the same path still wins over the host's, and the zero-length
placeholder the mount needs is recognisable (`prefix_lstat` `:139`) so a
later run remounts over it instead of reading it as a prefix file.

Two guards keep the mirror from escaping or misfiring. Parent directories
are created without following any symlink component (`mkdir_parents`
`:110`), because a prefix symlink with an absolute target (`tmp -> /tmp`,
`scripts/macify-setup-rootfs:144`) resolves against the host before the
chroot, and the leaf is opened `O_NOFOLLOW`. When the named path is not a
regular file, or the mount fails, the launcher exits 126 with a message
naming the jail and `MACIFY_NO_JAIL` (`:320-326`, `:439-445`) instead of
leaving a bare loader error.

### Evidence

- `printf 'a:b:c\nd:e:f\n' | scripts/macify tests/real/cat_macos` → the
  two lines, rc 0. Before: `open: No such file or directory`, rc 1.
- `printf 'x:y\n' | scripts/macify ~/cle-tmp/cat_macos` → `x:y`, rc 0
  (a host path outside the repo tree).
- `scripts/macify ~/cle-tmp/hello.sh` (`#!/bin/bash`) →
  `from-host-script`, rc 0: entry resolution still applies.
- `printf 'x\n' | scripts/macify ~/cle-tmp/tee_macos ~/cle-tmp/tee_macos`
  → `Read-only file system`, rc 1: the mirror is read-only.
- `scripts/macify tests/real/cat_macos /home/sd-v/Projects/mac-ify/Makefile`
  → `No such file or directory`: a host file argument is still hidden.
- `scripts/macify /home/sd-v/Projects/mac-ify` (a directory) and
  `scripts/macify /tmp/cle-src/cat` → the jail message, rc 126.
- `scripts/macify /usr/local/bin/bash -c 'echo hi'` → `hi`, rc 0.
- `make test` 17/17, `make test-real` 23/23, `make test-smoke` 29/29,
  `make test-functional` 103 pass / 0 fail / 1 skip.

### Adjacent, not fixed here

- `scripts/macify tests/real/cat_macos /tmp/t2.txt` runs the guest now,
  but the input is not printable: the jail does not expose host paths, so
  `/tmp/t2.txt` is not the host's file inside. Two pre-existing defects
  sit behind the error the guest reports. `<prefix>/tmp` is a symlink to
  `/tmp` (`scripts/macify-setup-rootfs:144`), which under chroot points at
  itself, so every `/tmp/...` open inside the jail is `ELOOP`; and the
  private tmpfs meant to give the guest scratch space (`src/jail.c:390-
  394`) is mounted at the host path before the chroot, so it is not what
  the guest sees. A host binary that lives under `/tmp` hits the same
  loop and is refused with the jail message, pointing at
  `MACIFY_NO_JAIL`.
- The mirrored file's sibling dylibs are not brought along: a host-path
  guest resolves its dependencies exactly as a prefix guest does.
