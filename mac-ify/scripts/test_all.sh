#!/bin/bash
cd /home/z/my-project/mac-ify

echo "=== Building ==="
make -C src 2>&1 | tail -3

echo ""
echo "=== jq test ==="
LD_LIBRARY_PATH=build timeout 15 ./build/macify tests/real/jq_darwin --help 2>&1 | grep -E 'cannot resolve|CRASH|calling main|exit|jq|Hello' | tail -10
echo "exit: ${PIPESTATUS[0]}"

echo ""
echo "=== Test suite ==="
python3 tests/run_tests.py 2>&1 | tail -10
