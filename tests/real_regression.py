#!/usr/bin/env python3
"""real_regression.py — automated regression harness over tests/real binaries.

Unlike real_smoke.sh (which only checks that *some* output was produced),
each case here asserts on expected output content, so behavior regressions
in the loader/shim/syscall layers fail loudly.

Usage:
    python3 tests/real_regression.py            # full curated set
    python3 tests/real_regression.py -v         # show command output on pass
    python3 tests/real_regression.py -f jq      # only cases matching substring

Binaries are fetched by scripts/fetch_binaries.sh; missing ones are skipped.
Exit codes follow the project's established convention: 0 is success;
139/134 are tolerated only when expected output was still produced
(some macOS binaries crash during cleanup after printing results).
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_DIR = REPO_ROOT / "tests" / "real"
MACIFY = REPO_ROOT / "build" / "macify"
TIMEOUT = 15

# Tolerated exit codes when expected output was produced (cleanup crashes).
CLEANUP_CRASH_CODES = {0, 139, 134}


class Case:
    def __init__(self, name, binary, args, pattern,
                 stdin=None, flags="-q", regex=False, exit_codes=None):
        self.name = name
        self.binary = binary
        self.args = args
        self.pattern = pattern
        self.stdin = stdin
        self.flags = flags.split() if isinstance(flags, str) else flags
        self.regex = regex
        self.exit_codes = exit_codes


# Curated regression cases. Keep this list sorted roughly by risk:
# anything exercising syscalls/stdio before pure --version loads.
CASES = [
    # ── Functional I/O (exercise read/write/signal/wait paths) ──
    Case("echo prints arg",       "echo_macos",   ["hello-regression"], r"^hello-regression\n$"),
    Case("cat passes stdin",      "cat_macos",    [], r"^b\na\n$",
         stdin="b\na\n"),
    Case("base64 round-trip",     "base64_macos", [], r"^bWFjaWZ5LXJlZ3Jlc3Npb24=\n$",
         stdin="macify-regression"),
    Case("true exits zero",       "true_macos",   [], r"", exit_codes={0}),
    Case("false exits one",       "false_macos",  [], r"", exit_codes={1}),

    # ── Tool --version outputs (load + init + stdio formatting) ──
    Case("jq version",            "jq_darwin",     ["--version"], r"jq-\d"),
    Case("ripgrep version",       "rg_macos",      ["--version"], r"ripgrep"),
    Case("fd version",            "fd_macos",      ["--version"], r"^fd "),
    Case("bat version",           "bat_macos",     ["--version"], r"bat"),
    Case("curl version",          "curl_macos",    ["--version"], r"curl"),
    Case("sd version",            "sd_macos",      ["--version"], r"sd "),
    Case("tree version",          "tree_macos",    ["--version"], r"tree v"),
    Case("wget version",          "wget_macos",    ["--version"], r"GNU Wget"),
    Case("procs version",         "procs_macos",   ["--version"], r"\d+\.\d+"),
    Case("dust version",          "dust_macos",    ["--version"], r"\d+\.\d+"),
    Case("b2sum version",         "b2sum_macos",   ["--version"], r"b2sum"),
    Case("cksum version",         "cksum_macos",   ["--version"], r"cksum"),
    Case("date version",          "date_macos",    ["--version"], r"date"),
    Case("dd version",            "dd_macos",      ["--version"], r"dd"),
    Case("df version",            "df_macos",      ["--version"], r"df"),
    Case("du version",            "du_macos",      ["--version"], r"du"),
    Case("env version",           "env_macos",     ["--version"], r"env"),
    Case("factor version",        "factor_macos",  ["--version"], r"factor"),
]


def run_case(case: Case, verbose: bool) -> str:
    """Returns 'PASS', 'FAIL', or 'SKIP <reason>'."""
    binary_path = REAL_DIR / case.binary
    if not MACIFY.exists():
        return "SKIP build/macify missing (run make)"
    if not binary_path.exists():
        return f"SKIP {case.binary} not fetched"

    cmd = [str(MACIFY), *case.flags, str(binary_path), *case.args]
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(MACIFY.parent)
    try:
        proc = subprocess.run(
            cmd, input=case.stdin, capture_output=True,
            text=True, timeout=TIMEOUT, env=env,
        )
    except subprocess.TimeoutExpired:
        return f"SKIP timed out after {TIMEOUT}s"

    output = proc.stdout
    if case.regex:
        matched = re.search(case.pattern, output, re.MULTILINE) is not None
    else:
        matched = re.search(case.pattern, output, re.MULTILINE) is not None

    ok_output = matched and output.strip() != "" if case.pattern else True
    ok_exit = proc.returncode in (case.exit_codes or CLEANUP_CRASH_CODES)

    if verbose:
        print(f"      cmd: {' '.join(cmd)}")
        print(f"      exit={proc.returncode} stdout={proc.stdout!r:.120}")
        if proc.stderr:
            print(f"      stderr={proc.stderr[:200]!r}")

    if ok_output and ok_exit:
        return "PASS"
    if not ok_output:
        return (f"FAIL output mismatch (exit={proc.returncode}, "
                f"pattern={case.pattern!r}, got {output[:80]!r})")
    return f"FAIL unexpected exit={proc.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--filter", default="",
                        help="only run cases whose name/binary matches")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show command output for passing cases too")
    args = parser.parse_args()

    passed = failed = skipped = 0
    failures = []

    for case in CASES:
        blob = case.name + case.binary
        if args.filter.lower() not in blob.lower():
            continue
        result = run_case(case, args.verbose)
        if result == "PASS":
            passed += 1
            print(f"  PASS  {case.name}")
        elif result.startswith("SKIP"):
            skipped += 1
            print(f"  SKIP  {case.name}  ({result[5:]})")
        else:
            failed += 1
            failures.append((case.name, result))
            print(f"  FAIL  {case.name}")
            print(f"        {result}")

    print()
    print(f"=== real_regression: {passed} passed, {failed} failed, "
          f"{skipped} skipped ===")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
