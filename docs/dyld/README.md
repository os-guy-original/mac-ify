# dyld / Mach-O ground truth

Upstream headers fetched from apple-oss-distributions (dyld and cctools
repos, main branch). Ground truth for the loader (`src/`) and fixup
decoding.

## Files

| File | Source | What it settles |
|---|---|---|
| `fixup-chains.h` | dyld `include/mach-o/fixup-chains.h` | Chain format codes: `DYLD_CHAINED_PTR_64=2`, `PTR_32=3`, `PTR_64_OFFSET=6` (there is **no** "bind=3" — see AUDIT macify.h entry). 64-bit rebase: `target=36` bits, `high8=8`, `next=11`; bind: `ordinal=24` bits, `addend=8` (bits 24–31) |
| `mach-o-loader.h` | cctools `include/mach-o/loader.h` | Load commands, segment/section structures, file type and flag bits |
| `dyld_images.h` | dyld `include/mach-o/dyld_images.h` | dyld_all_image_infos / dyld_image_info layout used for the guest-side info registration |

Cite these (with line numbers) in any change to `src/fixups.c`,
`src/segments.c`, `src/machify.h` struct definitions, or the fat/PIE
paths in `src/main.c`. The AUDIT.md findings for fixup-chains decoding
(ordinal/addend split, rebase target width, accepted pointer formats)
are all confirmed by `fixup-chains.h` as fetched.
