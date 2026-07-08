#!/usr/bin/env python3
"""
run_tests.py — Mac-ify v0.4 test suite runner.

Runs each test Mach-O binary through `macify` and verifies:
  - stdout output (where applicable)
  - exit code
  - side effects (file creation, etc.)

Also runs a benchmark comparing fast path vs slow path (--no-fast-path),
and includes tests for syscall argument translation (mmap flags, kill
signals, madvise advice).

Exit code 0 = all tests passed, non-zero = at least one failed.
"""

import os
import shutil
import subprocess
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MACIFY       = os.path.join(PROJECT_ROOT, 'build', 'macify')
BINARIES_DIR = os.path.join(PROJECT_ROOT, 'tests', 'binaries')

GREEN  = '\033[32m'
RED    = '\033[31m'
YELLOW = '\033[33m'
BOLD   = '\033[1m'
RESET  = '\033[0m'


class TestResult:
    PASS = 'PASS'
    FAIL = 'FAIL'
    SKIP = 'SKIP'


def run_case(name, binary, expect_stdout=None, expect_exit=0,
             expect_file=None, expect_file_content=None, args=None,
             extra_macify_args=None):
    """Run one test case. Returns (TestResult, message)."""
    if not os.path.isfile(MACIFY):
        return (TestResult.SKIP, f'macify binary not built at {MACIFY}')
    if not os.path.isfile(binary):
        return (TestResult.SKIP, f'test binary not found: {binary}')

    if expect_file and os.path.isfile(expect_file):
        os.remove(expect_file)

    cmd = [MACIFY, '-q']
    if extra_macify_args:
        cmd.extend(extra_macify_args)
    cmd.append(binary)
    if args:
        cmd.extend(args)

    # Set LD_LIBRARY_PATH so libmacify_shim.so can be found
    env = os.environ.copy()
    build_dir = os.path.join(PROJECT_ROOT, 'build')
    env['LD_LIBRARY_PATH'] = build_dir + ':' + env.get('LD_LIBRARY_PATH', '')

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, env=env)
    except subprocess.TimeoutExpired:
        return (TestResult.FAIL, 'timed out after 30s')

    stdout = proc.stdout.decode('utf-8', errors='replace')

    if expect_stdout is not None and stdout != expect_stdout:
        return (TestResult.FAIL,
                f'stdout mismatch\n  expected: {expect_stdout!r}\n  got:      {stdout!r}')

    if proc.returncode != expect_exit:
        return (TestResult.FAIL,
                f'exit code mismatch\n  expected: {expect_exit}\n  got:      {proc.returncode}')

    if expect_file:
        if not os.path.isfile(expect_file):
            return (TestResult.FAIL, f'expected file not created: {expect_file}')
        if expect_file_content is not None:
            with open(expect_file, 'rb') as f:
                actual = f.read()
            if actual != expect_file_content:
                return (TestResult.FAIL,
                        f'file content mismatch\n  expected: {expect_file_content!r}\n  got:      {actual!r}')

    return (TestResult.PASS, 'ok')


def run_benchmark():
    """Run bench.bin with fast path and slow path, return (fast_time, slow_time)."""
    bench_path = os.path.join(BINARIES_DIR, 'bench.bin')

    env = os.environ.copy()
    build_dir = os.path.join(PROJECT_ROOT, 'build')
    env['LD_LIBRARY_PATH'] = build_dir + ':' + env.get('LD_LIBRARY_PATH', '')

    # Fast path
    t0 = time.perf_counter()
    proc = subprocess.run([MACIFY, '-q', bench_path],
                          capture_output=True, timeout=60, env=env)
    t1 = time.perf_counter()
    fast_time = t1 - t0
    fast_ok = (proc.returncode == 0 and proc.stdout == b'done\n')

    # Slow path
    t0 = time.perf_counter()
    proc = subprocess.run([MACIFY, '-q', '--no-fast-path', bench_path],
                          capture_output=True, timeout=60, env=env)
    t1 = time.perf_counter()
    slow_time = t1 - t0
    slow_ok = (proc.returncode == 0 and proc.stdout == b'done\n')

    return fast_time, slow_time, fast_ok, slow_ok


TESTS = [
    {
        'name': 'hello — writes "Hello, Mac-ify!\\n" to stdout, exits 0',
        'binary': 'hello.bin',
        'expect_stdout': 'Hello, Mac-ify!\n',
        'expect_exit': 0,
    },
    {
        'name': 'exit42 — exits with code 42',
        'binary': 'exit42.bin',
        'expect_stdout': '',
        'expect_exit': 42,
    },
    {
        'name': 'compute — sums 1..10 = 55, exits with code 55',
        'binary': 'compute.bin',
        'expect_stdout': '',
        'expect_exit': 55,
    },
    {
        'name': 'argv — prints argv[0] (the binary path)',
        'binary': 'argv.bin',
        'expect_stdout': os.path.join(BINARIES_DIR, 'argv.bin') + '\n',
        'expect_exit': 0,
    },
    {
        'name': 'writefile — creates /tmp/macify-test.txt with "ok\\n"',
        'binary': 'writefile.bin',
        'expect_stdout': '',
        'expect_exit': 0,
        'expect_file': '/tmp/macify-test.txt',
        'expect_file_content': b'ok\n',
    },
    {
        'name': 'bench — 100,000 writes to /dev/null, prints "done"',
        'binary': 'bench.bin',
        'expect_stdout': 'done\n',
        'expect_exit': 0,
    },
    {
        'name': 'mmap — flag translation: MAP_ANON(0x1000) → MAP_ANONYMOUS(0x20)',
        'binary': 'mmap.bin',
        'expect_stdout': 'mmap-ok\n',
        'expect_exit': 0,
    },
    {
        'name': 'kill — signal translation: SIGURG(macOS 16) → SIGURG(Linux 23)',
        'binary': 'kill.bin',
        'expect_stdout': 'kill-ok\n',
        'expect_exit': 0,
    },
    {
        'name': 'madvise — advice translation: MADV_FREE(macOS 5) → MADV_FREE(Linux 8)',
        'binary': 'madvise.bin',
        'expect_stdout': 'madv-ok\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_dylib — dynamic linking: LC_LOAD_DYLIB + LC_DYLD_INFO binds + LC_MAIN',
        'binary': 'hello_dylib.bin',
        'expect_stdout': 'Hello, Mac-ify!\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_multi — rebases + non-lazy binds + lazy binds + stubs + 2 dylibs',
        'binary': 'hello_multi.bin',
        'expect_stdout': 'Hello, Mac-ify!\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_pie — ASLR/PIE: MH_PIE flag, random slide, rebase with nonzero slide',
        'binary': 'hello_pie.bin',
        'expect_stdout': 'Hello, Mac-ify!\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_sections — named sections: __text, __stubs, __cstring, __got, __la_symbol_ptr',
        'binary': 'hello_sections.bin',
        'expect_stdout': 'Hello, Mac-ify!\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_linkedit — __LINKEDIT segment: LC_SYMTAB + LC_DYSYMTAB + indirect sym table',
        'binary': 'hello_linkedit.bin',
        'expect_stdout': 'Hello, Mac-ify!\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_errno — macOS-specific __errno() from libmacify_shim.so',
        'binary': 'hello_errno.bin',
        'expect_stdout': 'Hello, Mac-ify!\nerrno-ok\n',
        'expect_exit': 0,
    },
    {
        'name': 'hello_tlv — TLV (Thread-Local Variables): __thread_vars + __thread_data + _tlv_bootstrap',
        'binary': 'hello_tlv.bin',
        'expect_stdout': 'tlv-ok\n',
        'expect_exit': 0,
    },
]


def main():
    if not os.path.isfile(MACIFY):
        print(f'{RED}ERROR{RESET}: macify not built. Run `make -C src` first.')
        return 1

    print(f'{BOLD}Mac-ify v0.4 Test Suite{RESET}')
    print(f'  binary: {MACIFY}')
    print()

    npass = nfail = nskip = 0
    for t in TESTS:
        binary_path = os.path.join(BINARIES_DIR, t['binary'])
        result, msg = run_case(
            name=t['name'],
            binary=binary_path,
            expect_stdout=t.get('expect_stdout'),
            expect_exit=t.get('expect_exit', 0),
            expect_file=t.get('expect_file'),
            expect_file_content=t.get('expect_file_content'),
            args=t.get('args'),
        )
        if result == TestResult.PASS:
            npass += 1
            print(f'  {GREEN}PASS{RESET}  {t["name"]}')
        elif result == TestResult.FAIL:
            nfail += 1
            print(f'  {RED}FAIL{RESET}  {t["name"]}')
            for line in msg.splitlines():
                print(f'         {line}')
        else:
            nskip += 1
            print(f'  {YELLOW}SKIP{RESET}  {t["name"]}')
            print(f'         {msg}')

    # Benchmark comparison
    print()
    print(f'{BOLD}Benchmark: 100,000 writes to /dev/null{RESET}')
    fast_time, slow_time, fast_ok, slow_ok = run_benchmark()

    if fast_ok and slow_ok:
        speedup = slow_time / fast_time if fast_time > 0 else float('inf')
        print(f'  {GREEN}fast path{RESET} (immediate patching):  {fast_time*1000:8.1f} ms')
        print(f'  {YELLOW}slow path{RESET} (SIGILL handler):      {slow_time*1000:8.1f} ms')
        print(f'  {BOLD}speedup{RESET}:                            {speedup:8.1f}x')
    else:
        if not fast_ok:
            print(f'  {RED}fast path FAILED{RESET}')
            nfail += 1
        if not slow_ok:
            print(f'  {RED}slow path FAILED{RESET}')
            nfail += 1

    print()
    total = len(TESTS)
    print(f'{BOLD}Results:{RESET} {GREEN}{npass} passed{RESET}, '
          f'{RED}{nfail} failed{RESET}, {YELLOW}{nskip} skipped{RESET} '
          f'({total} total)')

    return 0 if nfail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
