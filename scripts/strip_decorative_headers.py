#!/usr/bin/env python3
"""Convert decorative '/* ====...==== */' comment headers to plain comments.

Transforms patterns like:
    /* ============================================================
     * Title — description.
     * ============================================================ */
into:
    /* Title — description. */

Operates on multiple files. Preserves inner content lines that start with ' * '.
"""
import re
import sys

FILES = [
    "/home/z/my-project/mac-ify/src/fixups.c",
    "/home/z/my-project/mac-ify/src/syscall.c",
    "/home/z/my-project/mac-ify/src/main.c",
    "/home/z/my-project/mac-ify/src/segments.c",
    "/home/z/my-project/mac-ify/src/runtime.c",
    "/home/z/my-project/mac-ify/shim/libmacify_shim.c",
]

# Pattern: opening '/* ====' line, middle ' * ...' lines, closing ' * ====' line
HEADER_RE = re.compile(
    r'/\* =+\n'                       # opening: /* =====
    r'((?:[ \t]*\ \*[^\n]*\n)+?)'     # middle: one or more ' * ...' lines
    r'[ \t]*\ \*\ =+\ \*/\n',         # closing: * ===== */
    re.MULTILINE,
)


def transform_middle(middle: str) -> str:
    """Convert middle ' * ...' lines to plain ' * ...' (kept) but drop
    leading/trailing empty ' *' lines."""
    lines = middle.splitlines()
    # Drop the leading ' * ' prefix from each line
    cleaned = []
    for line in lines:
        # Match ' * content' or ' *' (empty)
        if re.match(r'^[ \t]*\ \*\ ', line):
            cleaned.append(line[3:])  # strip ' * '
        elif re.match(r'^[ \t]*\ \*$', line):
            cleaned.append('')  # blank line in body
        else:
            cleaned.append(line)
    # Strip leading and trailing blank lines
    while cleaned and cleaned[0].strip() == '':
        cleaned.pop(0)
    while cleaned and cleaned[-1].strip() == '':
        cleaned.pop()
    if not cleaned:
        return ''
    # If only one line, no newlines needed
    if len(cleaned) == 1:
        return f"/* {cleaned[0]} */\n"
    # Multi-line: /* first line\n * next line...\n */
    body = '/* ' + cleaned[0] + '\n'
    for line in cleaned[1:]:
        body += f" * {line}\n"
    body += ' */\n'
    return body


def transform_file(path: str) -> int:
    with open(path) as f:
        text = f.read()

    def repl(m):
        return transform_middle(m.group(1))

    new_text, n = HEADER_RE.subn(repl, text)
    if n > 0:
        with open(path, 'w') as f:
            f.write(new_text)
    return n


total = 0
for path in FILES:
    n = transform_file(path)
    print(f"  {path}: {n} headers converted")
    total += n
print(f"\nTotal: {total} decorative headers converted to plain comments.")
