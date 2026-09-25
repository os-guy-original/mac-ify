# Go runtime ground truth

`runtime2.go-go1.26.4.txt` — upstream `src/runtime/runtime2.go` from
golang/go at tag go1.26.4 (the Go version real-world test binaries are
built with; check with `strings <bin> | grep ^go1.`). License in
`LICENSE-go1.26.4`.

Used to verify the struct offsets the shim hard-codes when wrapping Go
internals (linux/amd64):

| Field | Offset | Verified by |
|---|---|---|
| `m.g0` | 0x00 | field-order computation + compiled probe |
| `m.gsignal` | 0x48 | same (`go_signal.c:go_is_ready` reads m+0x48 ✓) |
| `m.curg` | 0xB8 | same |
| `g.m` | 0x30 | same (`go_signal.c` reads g+0x30 ✓) |
| `g.sched` | 0x38..0x68 | `sp@0x38 pc@0x40 g@0x48 ctxt@0x50 lr@0x58 bp@0x60` — `patch_go_systemstack` reads `[g+0x38]` (sched.sp ✓) and restores rbp from the byte the binary itself encodes |

Re-verify with a compiled probe whenever a guest binary is built with a
newer Go: layout depends on field order, which upstream changes rarely
but does change. The 1.26→1.27 m-struct field list already differs (1.26
keeps `divmod` without the extra pad comment; sizes on amd64 unchanged,
offsets verified identical), so treat "new Go release" as a trigger for
this check.
