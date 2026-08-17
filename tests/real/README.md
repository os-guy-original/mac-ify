# Test Binaries

This directory holds the real macOS x86_64 binaries used for integration
testing of the macify translator. The binaries are **not committed** to the
repository — they are fetched on demand by `scripts/fetch_binaries.sh`.

## Fetching binaries

```bash
./scripts/fetch_binaries.sh
```

This downloads pre-built macOS binaries from MacPorts and GitHub releases
and places them here as `*_macos` (e.g. `bat_macos`, `cat_macos`, `jq_darwin`).

## Running tests

macify has three test layers, each in a sensible place:

| Layer             | Path                         | What it checks                              |
|-------------------|------------------------------|---------------------------------------------|
| Synthesized unit  | `tests/run_tests.py`         | Hand-built Mach-O binaries (built by `scripts/gen_macho.py`) exercising individual loader features: PIE, chained fixups, lazy/non-lazy binds, TLVs, syscall flag translation. |
| Real-binary smoke | `tests/real_smoke.sh`        | `--version` (and a few trivial) smoke tests against fetched macOS binaries. Fast. |
| Real-binary func  | `tests/real_functional.sh`   | Comprehensive functional tests: real stdin/stdout pipelines, JSON/CSV/SQL processing, file mgmt, compression, etc. Slow. |

Make targets:

```bash
make test              # synthesized unit tests
make test-smoke        # real-binary --version smoke tests
make test-functional   # real-binary functional tests
```

## Adding a new test binary

1. Add a fetch entry to `scripts/fetch_binaries.sh`
2. Run the fetch script to download the binary
3. Add a smoke check to `tests/real_smoke.sh`
4. If the binary has a meaningful behaviour to verify, also add a functional
   check to `tests/real_functional.sh` (functional checks are preferred when
   possible — they exercise more of the loader path than `--version` does).
