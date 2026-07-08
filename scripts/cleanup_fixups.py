#!/usr/bin/env python3
"""Surgical cleanup of /home/z/my-project/mac-ify/src/fixups.c.

Removes the massive rambling comment block (lines 544-1013) that explored
dead-end theories about chained-fixup bit positions, and replaces it with
a tight 18-line documentation block. Also removes the dead `fixup_ptr`
local that was never used.
"""
import sys

PATH = "/home/z/my-project/mac-ify/src/fixups.c"

with open(PATH, "r") as f:
    lines = f.readlines()

# Sanity-check: lines 540..543 (1-indexed) are:
#   540: "/* page_start is the byte offset within the page to the first fixup */"
#   541: "            uint8_t *page_base = ..."
#   542: "            uint8_t *fixup_ptr = page_base + page_start;"   <- dead
#   543: ""
#   544: "            /* Stride for chained fixups..."  <- start of rambling

assert "page_start is the byte offset" in lines[539], f"line 540 mismatch: {lines[539]!r}"
assert "fixup_ptr = page_base + page_start" in lines[541], f"line 542 mismatch: {lines[541]!r}"
assert "Stride for chained fixups" in lines[543], f"line 544 mismatch: {lines[543]!r}"

single_chain_idx = None
for i, line in enumerate(lines[543:], start=543):
    if "Single-chain fixup walking" in line:
        single_chain_idx = i
        break
assert single_chain_idx is not None, "could not find 'Single-chain fixup walking'"
print(f"Rambling block: lines 544..{single_chain_idx+1}")

page_end_idx = None
for i in range(single_chain_idx, len(lines)):
    if "uint8_t *page_end = page_base + page_size" in lines[i]:
        page_end_idx = i
        break
assert page_end_idx is not None, "could not find page_end decl"
print(f"Doc block ends at line {page_end_idx+1} (0-idx {page_end_idx})")

REPLACEMENT = """\
            /* Walk the single fixup chain for this page.
             *
             * Apple's 64-bit chained fixup entry (8 bytes):
             *   bit  63      : bind flag (0=rebase, 1=bind)
             *   bits 51-62   : next (12 bits, in units of 4 bytes)
             *   bits 43-50   : high8 (rebase only -- extends target above 2^43)
             *
             * Rebase:  bits 0-42  = offset from image base (43 bits)
             *          runtime   = ((high8 << 43) | offset) + load_base
             * Bind:    bits 0-15 = ordinal (0-based import index)
             *          bits 16-31 = addend
             *
             * One chain per page, starting at page_start, linked by `next`
             * (byte offset = next * 4) until next == 0. Special ordinals
             * 0xFD/0xFE/0xFF (flat-lookup / main-exec / self) are not
             * supported and left as-is.
             */
"""

new_lines = []
new_lines.extend(lines[0:539])               # everything up to (not incl) page_start comment
new_lines.append(lines[540])                  # page_base decl (keep)
new_lines.append("\n")                        # blank line
new_lines.append(REPLACEMENT)                 # new doc block
new_lines.extend(lines[page_end_idx:])        # the actual code

with open(PATH, "w") as f:
    f.writelines(new_lines)

print(f"Wrote {len(new_lines)} lines (was {len(lines)})")
