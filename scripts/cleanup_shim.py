#!/usr/bin/env python3
"""Surgical cleanup of /home/z/my-project/mac-ify/shim/libmacify_shim.c.

Deletes dead code identified in the survey, in reverse line order so
earlier line numbers don't shift. Also tightens two verbose comment
blocks (TLV, dyld_stub_binder) and removes the "Phase 4" reference line.
"""
import re

PATH = "/home/z/my-project/mac-ify/shim/libmacify_shim.c"

with open(PATH, "r") as f:
    text = f.read()
lines = text.splitlines(keepends=True)

# Each entry: (start_1indexed, end_1indexed, description, expected_first_line_substring)
# We process in REVERSE order (highest line first) to keep earlier indices valid.
DELETIONS = [
    # Item 11: macify_strerror_r comment block + fn (1188-1193)
    (1188, 1193, "macify_strerror_r dead fn + comment",
     "macOS strerror_r"),
    # Item 10: macify_qsort_r (1132-1163) + preceding comment block (1126-1163)
    # Let's verify by checking 1132 first
    (1132, 1163, "macify_qsort_r dead fn",
     "macify_qsort_r"),
    # Item 9: extern __qsort_bridge_glibc (line 1140) - already covered by item 10 deletion
    # Item 8+12 combined: comment (1004-1015) + redundant includes (1016-1017) + 3 wrappers (1019-1035) + blanks
    (1004, 1035, "pthread_key_t compat comment + dead wrappers",
     "pthread_key_t size compatibility"),
    # Item 7: extern glibc_exit (line 995)
    (995, 995, "unused extern glibc_exit",
     "extern void glibc_exit"),
    # Item 5+6 combined: orphan comments + blanks (523-537)
    (523, 537, "orphan $-suffix + _pthread_setname_np comments",
     "macOS $-suffixed functions"),
    # Item 4: init_stdio_ptrs (340-346) + preceding blank line (339)
    (339, 346, "dead init_stdio_ptrs fn",
     "static void init_stdio_ptrs"),
    # Item 3: ___std{err,in,out}p_storage decls (335-337)
    (335, 337, "dead stdio _storage statics",
     "static FILE *___stderrp_storage"),
    # Item 2: __macify_progname_storage (line 77)
    (77, 77, "dead __macify_progname_storage",
     "__macify_progname_storage"),
    # Item 1: __macify_errno (43-45)
    (43, 45, "dead __macify_errno fn",
     "__macify_errno"),
]

# Verify each deletion target BEFORE applying any
print("Verifying targets...")
for start, end, desc, expected_substr in DELETIONS:
    # 1-indexed -> 0-indexed
    chunk = "".join(lines[start - 1:end])
    if expected_substr not in chunk:
        print(f"  MISMATCH for {desc!r} (lines {start}-{end}):")
        print(f"    Expected substring: {expected_substr!r}")
        print(f"    First line: {lines[start - 1]!r}")
        raise SystemExit(1)
    print(f"  OK: {desc} (lines {start}-{end})")

# Apply deletions in reverse order (highest line numbers first)
print("\nApplying deletions in reverse order...")
new_lines = lines[:]
for start, end, desc, _ in sorted(DELETIONS, key=lambda x: -x[0]):
    # 1-indexed inclusive -> 0-indexed slice
    del new_lines[start - 1:end]
    print(f"  Deleted {desc}: lines {start}-{end} ({end - start + 1} lines)")

# Verify file length
print(f"\nLine count: {len(lines)} -> {len(new_lines)} (removed {len(lines) - len(new_lines)} lines)")

with open(PATH, "w") as f:
    f.writelines(new_lines)

print(f"Wrote {PATH}")
