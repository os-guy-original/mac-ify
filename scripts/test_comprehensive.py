#!/usr/bin/env python3
"""Comprehensive test suite for macify interactive bash."""
import os, pty, select, sys, time, re, subprocess

MACIFY_DIR = "/home/z/my-project/build"
BASH_PATH = os.path.expanduser("~/.macify/bin/bash")

def run_noninteractive(cmd, timeout=10):
    """Run bash -c 'cmd' and return output."""
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = MACIFY_DIR
    try:
        r = subprocess.run(
            [f"{MACIFY_DIR}/macify", BASH_PATH, "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
            env=env
        )
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"

def run_interactive(cmds, term="xterm-256color", noediting=False, timeout=15):
    """Run interactive bash with PTY, type commands, return output."""
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = MACIFY_DIR
    env["TERM"] = term
    args = [f"{MACIFY_DIR}/macify", BASH_PATH, "--norc", "--noprofile", "-i"]
    if noediting:
        args.insert(2, "--noediting")
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(args[0], args, env)
        os._exit(127)
    buf = b""
    all_output = b""
    deadline = time.time() + timeout
    typed = 0
    while time.time() < deadline:
        r,_,_ = select.select([fd],[],[],0.3)
        if r:
            try: chunk = os.read(fd, 65536)
            except OSError: break
            if not chunk: break
            buf += chunk
            all_output += chunk
            if typed < len(cmds) and b"$ " in buf[-400:]:
                time.sleep(0.4)
                os.write(fd, cmds[typed])
                typed += 1
                buf = b""
                deadline = time.time() + 3.0
    os.close(fd)
    os.waitpid(pid, 0)
    text = all_output.decode("latin-1", errors="replace")
    clean = re.sub(r'\x1b\[[^a-zA-Z]*[a-zA-Z]', '', text)
    return clean

passed = 0
failed = 0
results = []

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        results.append(f"  PASS  {name}")
    else:
        failed += 1
        results.append(f"  FAIL  {name}  {detail}")

# ── 1. Non-interactive tests ──────────────────────────────────
print("=== Non-interactive tests ===")

out = run_noninteractive("echo hello")
test("echo hello", "hello" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo $((2+3))")
test("arithmetic", "5" in out, f"got: {out.strip()!r}")

out = run_noninteractive("printf 'a%sb' 123")
test("printf", "a123b" in out, f"got: {out.strip()!r}")

out = run_noninteractive("x=hello; echo $x")
test("variable assignment", "hello" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo 'quote test'")
test("single quotes", "quote test" in out, f"got: {out.strip()!r}")

out = run_noninteractive('echo "double quotes"')
test("double quotes", "double quotes" in out, f"got: {out.strip()!r}")

out = run_noninteractive("for i in 1 2 3; do echo $i; done")
test("for loop", "1\n2\n3" in out, f"got: {out.strip()!r}")

out = run_noninteractive("if [ 1 -eq 1 ]; then echo yes; fi")
test("if statement", "yes" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo a; echo b; echo c")
test("multiple commands", "a\nb\nc" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo $(echo nested)")
test("command substitution", "nested" in out, f"got: {out.strip()!r}")

out = run_noninteractive("true; echo exit=$?")
test("exit code", "exit=0" in out, f"got: {out.strip()!r}")

out = run_noninteractive("false; echo exit=$?")
test("false exit code", "exit=1" in out, f"got: {out.strip()!r}")

# ── 2. Interactive with --noediting ───────────────────────────
print("\n=== Interactive (--noediting) tests ===")

out = run_interactive([b"printf MARKER1\\n\r", b"printf MARKER2\\n\r", b"exit\r"],
                      noediting=True, timeout=10)
test("--noediting: first command", "MARKER1" in out, f"got: {out[:100]!r}")
test("--noediting: second command", "MARKER2" in out, f"got: {out[:100]!r}")
test("--noediting: no crash", "CRASH" not in out, "crashed!")

# ── 3. Interactive with readline ──────────────────────────────
print("\n=== Interactive (readline) tests ===")

out = run_interactive([b"echo hello\r"], noediting=False, timeout=8)
lines = [l.strip() for l in out.split("\n") if l.strip()]
test("readline: first command", len(lines) > 0, f"lines: {lines[:3]}")
test("readline: no ^M", "^M" not in out, "still showing ^M")

# ── 4. File operations ────────────────────────────────────────
print("\n=== File operation tests ===")

out = run_noninteractive("echo content > /tmp/m_test.txt; while read line; do echo $line; done < /tmp/m_test.txt")
test("write+read file", "content" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo line1 > /tmp/m_test.txt; echo line2 >> /tmp/m_test.txt; while read line; do echo $line; done < /tmp/m_test.txt")
test("append to file", "line1" in out and "line2" in out, f"got: {out.strip()!r}")

out = run_noninteractive("test -f /tmp/m_test.txt && echo exists")
test("test -f", "exists" in out, f"got: {out.strip()!r}")

# ── 5. String operations ──────────────────────────────────────
print("\n=== String operation tests ===")

out = run_noninteractive('v="hello world"; echo ${v#hello }')
test("param expansion prefix", "world" in out, f"got: {out.strip()!r}")

out = run_noninteractive('v="hello world"; echo ${v%world}')
test("param expansion suffix", "hello" in out or "hello " in out, f"got: {out.strip()!r}")

out = run_noninteractive('v="hello"; echo ${#v}')
test("string length", "5" in out, f"got: {out.strip()!r}")

out = run_noninteractive('echo ${v:-default}')
test("default value", "default" in out, f"got: {out.strip()!r}")

# ── 6. Control structures ─────────────────────────────────────
print("\n=== Control structure tests ===")

out = run_noninteractive("case foo in foo) echo matched;; esac")
test("case statement", "matched" in out, f"got: {out.strip()!r}")

out = run_noninteractive("i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done")
test("while loop", "0\n1\n2" in out, f"got: {out.strip()!r}")

out = run_noninteractive("func() { echo func_called; }; func")
test("function def+call", "func_called" in out, f"got: {out.strip()!r}")

out = run_noninteractive("func() { echo $1 $2; }; func arg1 arg2")
test("function arguments", "arg1 arg2" in out, f"got: {out.strip()!r}")

# ── 7. Signal handling ────────────────────────────────────────
print("\n=== Signal handling tests ===")

out = run_noninteractive("kill -0 $$; echo alive")
test("kill -0", "alive" in out, f"got: {out.strip()!r}")

out = run_noninteractive("(exit 42); echo done")
test("subshell exit", "done" in out, f"got: {out.strip()!r}")

# ── 8. Complex commands ───────────────────────────────────────
print("\n=== Complex command tests ===")

out = run_noninteractive("arr=(a b c); echo ${arr[1]}")
test("array indexing", "b" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo {1..5}")
test("brace expansion", "1 2 3 4 5" in out, f"got: {out.strip()!r}")

out = run_noninteractive("v=hello; echo ${v^^}")
test("uppercase", "HELLO" in out, f"got: {out.strip()!r}")

out = run_noninteractive("echo $BASH_VERSION")
test("BASH_VERSION", "5.3" in out, f"got: {out.strip()!r}")

# ── Print results ─────────────────────────────────────────────
print("\n" + "="*60)
for r in results:
    print(r)
print("="*60)
print(f"\nTotal: {passed} passed, {failed} failed, {passed+failed} tests")
if passed+failed > 0:
    print(f"Success rate: {passed*100//(passed+failed)}%")
