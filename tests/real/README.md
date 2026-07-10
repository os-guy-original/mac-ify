# Test Binaries

This directory contains macOS x86_64 binaries used for integration testing
the macify translator. The binaries are **not committed** to the repository
— they are fetched on demand by `scripts/fetch_binaries.sh`.

## Fetching binaries

```bash
./scripts/fetch_binaries.sh
```

This downloads pre-built macOS binaries from MacPorts and GitHub releases
and places them here as `*_macos` (e.g. `bat_macos`, `cat_macos`, `jq_macos`).

## Running tests

```bash
make test-real      # basic --version / functional smoke tests
./scripts/functional_tests.sh   # comprehensive functional tests
```

## Adding a new test binary

1. Add a fetch entry to `scripts/fetch_binaries.sh`
2. Run the fetch script to download the binary
3. Add a test case to `scripts/functional_tests.sh`
