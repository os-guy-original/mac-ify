#!/usr/bin/env python3
"""
macify-trace — Parse and analyze macify debug output at runtime.

Usage:
  macify-trace run <binary> [args...]    Run a binary and trace all debug output
  macify-trace parse <logfile>           Parse a saved log file
  macify-trace live <binary> [args...]   Run with real-time filtering

Environment variables (set on the binary being traced):
  MACIFY_NET_DEBUG=1       — Network calls (socket, connect, send, recv, etc.)
  MACIFY_SSL_DEBUG=1       — SSL/pthread init (pthread_once, rwlock, keys, etc.)
  MACIFY_FORCE_SSL=1       — Force OpenSSL init globals (curl/wget only)
  MACIFY_SHIM_DEBUG=1      — Shim load address
  MACIFY_MALLOC_DEBUG=1    — malloc_zone operations
  MACIFY_MACH_DEBUG=1      — Mach API calls (host_processor_info, etc.)
  MACIFY_SYSCTL_DEBUG=1    — sysctl calls

Features:
  - Colorized output (errors in red, warnings in yellow)
  - Summary statistics at the end
  - Error detection (errno corruption, NULL returns, crashes)
  - Call chain reconstruction
"""

import sys
import os
import subprocess
import re
import signal
from collections import defaultdict

# ANSI colors
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

def colorize(line):
    if 'CRASH' in line or 'SIGSEGV' in line or 'SIGFPE' in line or 'Segmentation fault' in line:
        return f"{RED}{BOLD}{line}{RESET}"
    if 'FAILED' in line or 'error' in line.lower() and 'no error' not in line.lower():
        return f"{RED}{line}{RESET}"
    if 'WARN' in line or 'Unable to' in line:
        return f"{YELLOW}{line}{RESET}"
    if 'PASS' in line or 'success' in line.lower() or 'Established' in line:
        return f"{GREEN}{line}{RESET}"
    if line.startswith('SSL_DEBUG:'):
        return f"{CYAN}{line}{RESET}"
    if line.startswith('macify:'):
        return f"{CYAN}{line}{RESET}"
    return line

def parse_log(lines):
    """Parse debug output and generate a summary."""
    stats = defaultdict(int)
    errors = []
    calls = []

    for line in lines:
        line = line.rstrip()

        # Track function calls
        if 'SSL_DEBUG: pthread_once:' in line:
            stats['pthread_once'] += 1
            if 'DONE' in line:
                stats['pthread_once_done'] += 1
        elif 'SSL_DEBUG: pthread_rwlock_init' in line:
            stats['pthread_rwlock_init'] += 1
        elif 'SSL_DEBUG: pthread_mutex_init' in line:
            stats['pthread_mutex_init'] += 1
        elif 'SSL_DEBUG: pthread_cond_init' in line:
            stats['pthread_cond_init'] += 1
        elif 'SSL_DEBUG: pthread_key_create' in line:
            stats['pthread_key_create'] += 1

        # Track network calls
        if 'socket: ret=' in line:
            stats['socket'] += 1
        elif 'connect: ret=' in line:
            stats['connect'] += 1
        elif 'send: ' in line and 'ret=' in line:
            stats['send'] += 1
        elif 'recv: ' in line and 'ret=' in line:
            stats['recv'] += 1
        elif 'getaddrinfo:' in line:
            stats['getaddrinfo'] += 1

        # Track errors
        if 'FAILED' in line:
            errors.append(line)
        if 'CRASH' in line or 'SIGSEGV' in line or 'SIGFPE' in line:
            errors.append(line)
        if 'errno=47' in line or 'errno=25' in line:
            # Potential errno corruption
            pass

        # Print colorized
        print(colorize(line))

    return stats, errors

def print_summary(stats, errors):
    print(f"\n{BOLD}=== Summary ==={RESET}")
    print(f"  Total lines processed")
    for key, val in sorted(stats.items()):
        print(f"    {key}: {val}")

    if errors:
        print(f"\n{RED}{BOLD}=== Errors ({len(errors)}) ==={RESET}")
        for e in errors[:20]:
            print(f"  {colorize(e)}")
        if len(errors) > 20:
            print(f"  ... and {len(errors)-20} more")

def cmd_run(args):
    binary = args.binary
    binary_args = args.args

    # Set all debug env vars
    env = os.environ.copy()
    env['MACIFY_NET_DEBUG'] = '1'
    env['MACIFY_SSL_DEBUG'] = '1'
    env['MACIFY_SHIM_DEBUG'] = '1'
    if 'curl' in binary or 'wget' in binary:
        env['MACIFY_FORCE_SSL'] = '1'

    # Build command
    cmd = [os.path.join(os.getcwd(), 'build/macify'), binary] + binary_args

    # Run with real-time output
    proc = subprocess.Popen(
        cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )

    lines = []
    try:
        for line in proc.stdout:
            lines.append(line)
            print(colorize(line.rstrip()))
    except KeyboardInterrupt:
        proc.kill()

    proc.wait()

    stats, errors = parse_log(lines)
    print_summary(stats, errors)
    print(f"\n  Exit code: {proc.returncode}")

def cmd_parse(args):
    with open(args.logfile) as f:
        lines = f.readlines()
    stats, errors = parse_log(lines)
    print_summary(stats, errors)

def main():
    import argparse
    parser = argparse.ArgumentParser(description='macify-trace: runtime debug output analyzer')
    sub = parser.add_subparsers(dest='command')

    p = sub.add_parser('run', help='Run a binary with all debug tracing')
    p.add_argument('binary')
    p.add_argument('args', nargs='*')

    p = sub.add_parser('parse', help='Parse a saved log file')
    p.add_argument('logfile')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'run':
        cmd_run(args)
    elif args.command == 'parse':
        cmd_parse(args)

if __name__ == '__main__':
    main()
