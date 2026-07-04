# mac-ify Debug Toolkit

Tools for debugging macOS binaries running through the mac-ify translator.

## Quick Start

```bash
# Set up PATH
export PATH=$PATH:/home/z/my-project/mac-ify/scripts/debug

# Disassemble a function
macify-debug disasm tests/real/curl_macos SSL_CTX_new_ex --after 60

# Find callers of a function
macify-debug callers tests/real/curl_macos SSL_CTX_new_ex

# Search for symbols
macify-debug symbols tests/real/curl_macos --search _Default

# Analyze a crash (needs runtime RIP and slide from macify output)
macify-debug crash tests/real/curl_macos 0x7f1234567890 0x7f1200000000 --regs rax=0x42

# Run with full tracing
macify-trace run tests/real/curl_macos -sv https://httpbin.org/get
```

## Tools

### macify-debug.py — Static Binary Analysis

Static analysis of Mach-O binaries using LIEF + capstone. Works on the binary
file directly (no execution needed).

| Command | Description |
|---------|-------------|
| `disasm` | Disassemble around a symbol/address, with call target resolution |
| `symbols` | List/search symbols (imports, exports, all) |
| `callers` | Find all call sites of a function |
| `callees` | List all functions called by a function |
| `strings` | Search __cstring section |
| `struct-offset` | Find code that accesses a struct field at a given offset |
| `xref` | Find all references to an address (LEA + data pointers) |
| `crash` | Map runtime crash addresses to static symbols + disassemble |
| `trace` | Recursive call trace from a function (depth-limited) |

### macify-trace.py — Runtime Trace Analyzer

Runs a binary through macify with all debug env vars enabled, colorizes
output, and generates a summary of function calls and errors.

| Command | Description |
|---------|-------------|
| `run` | Run binary with all MACIFY_*_DEBUG=1, colorize + summarize |
| `parse` | Parse a saved log file |

## Debug Environment Variables

Set these on the macify process to enable tracing:

| Variable | What it traces |
|----------|---------------|
| `MACIFY_NET_DEBUG=1` | socket, connect, send, recv, getaddrinfo, poll |
| `MACIFY_SSL_DEBUG=1` | pthread_once, rwlock, mutex, cond, key operations |
| `MACIFY_FORCE_SSL=1` | Force OpenSSL init globals (curl/wget only) |
| `MACIFY_SHIM_DEBUG=1` | Shim load address |
| `MACIFY_MALLOC_DEBUG=1` | malloc_zone_malloc/realloc/free |
| `MACIFY_MACH_DEBUG=1` | host_processor_info, munmap |
| `MACIFY_SYSCTL_DEBUG=1` | sysctl name/value |

## Usage Patterns

### Finding a crash

1. Run the binary and capture the crash:
```bash
LD_LIBRARY_PATH=build ./build/macify tests/real/htop_macos 2>&1 | tee /tmp/crash.log
```

2. Extract the runtime RIP and slide from the output:
```
macify: mapped __TEXT  vm=0x7f1234560000  (slide=0x7f1200000000)
...
rip=00007f1234567890
```

3. Analyze:
```bash
macify-debug crash tests/real/htop_macos 0x7f1234567890 0x7f1200000000
```

### Finding struct layout bugs

The _DefaultRuneLocale bug was found by checking what offset the binary accesses:

```bash
# Find where the binary reads _DefaultRuneLocale + offset 0x3c
macify-debug struct-offset tests/real/curl_macos _DefaultRuneLocale 0x3c

# Disassemble the function that accesses it
macify-debug disasm tests/real/curl_macos CONF_parse_list --after 60
```

### Tracing SSL failures

```bash
# Run with full SSL tracing
MACIFY_SSL_DEBUG=1 MACIFY_FORCE_SSL=1 LD_LIBRARY_PATH=build \
  ./build/macify tests/real/curl_macos -sv https://httpbin.org/get 2>&1 | \
  grep SSL_DEBUG
```

## Python Dependencies

```bash
pip install lief capstone
```
