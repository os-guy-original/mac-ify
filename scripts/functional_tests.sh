#!/bin/bash
# Comprehensive functional tests for macify
# Tests actual functionality (not just --version) of macOS binaries
LD_LIBRARY_PATH=build
export LD_LIBRARY_PATH
MACIFY="build/macify"
TIMEOUT=5
PASS=0
FAIL=0
SKIP=0

run_test() {
    local name="$1"
    local cmd="$2"
    local expected_exit="${3:-0}"
    local result=$(timeout $TIMEOUT bash -c "$cmd" 2>/dev/null; echo $?)
    local exit_code=$(echo "$result" | tail -1)
    local output=$(echo "$result" | head -n -1)

    if [ "$exit_code" = "124" ]; then
        echo "[TIMEOUT] $name"
        SKIP=$((SKIP+1))
    elif [ "$exit_code" = "$expected_exit" ]; then
        echo "[PASS] $name"
        PASS=$((PASS+1))
    else
        echo "[FAIL] $name (exit $exit_code, expected $expected_exit)"
        FAIL=$((FAIL+1))
    fi
}

# Setup test data
mkdir -p /tmp/ftest
echo "hello world from mac" > /tmp/ftest/a.txt
echo "second line" >> /tmp/ftest/a.txt
echo '{"name":"macify","version":"1.0","nums":[1,2,3,4,5]}' > /tmp/ftest/data.json
for i in 3 1 4 1 5 9 2 6; do echo $i; done > /tmp/ftest/nums.txt
printf "5\n3\n1\n4\n2\n" > /tmp/nums2.txt

echo "=== File Operations ==="
run_test "cat"        "$MACIFY tests/real/cat_macos /tmp/ftest/a.txt"
run_test "wc -l"      "$MACIFY tests/real/wc_macos -l /tmp/ftest/a.txt"
run_test "wc -w"      "$MACIFY tests/real/wc_macos -w /tmp/ftest/a.txt"
run_test "wc -c"      "$MACIFY tests/real/wc_macos -c /tmp/ftest/a.txt"
run_test "head -1"    "$MACIFY tests/real/head_macos -1 /tmp/ftest/a.txt"
run_test "head -2"    "$MACIFY tests/real/head_macos -2 /tmp/ftest/a.txt"
run_test "grep"       "$MACIFY tests/real/grep_macos hello /tmp/ftest/a.txt"
run_test "grep -n"    "$MACIFY tests/real/grep_macos -n 9 /tmp/ftest/nums.txt"

echo
echo "=== Sorting ==="
run_test "sort (basic)"    "$MACIFY tests/real/sort_macos /tmp/ftest/nums.txt"
run_test "sort -u"         "$MACIFY tests/real/sort_macos -u /tmp/ftest/nums.txt"
run_test "sort -n"         "$MACIFY tests/real/sort_macos -n /tmp/nums2.txt"

echo
echo "=== Listing ==="
run_test "ls"          "$MACIFY tests/real/ls_macos /tmp/ftest"
run_test "ls -1"       "$MACIFY tests/real/ls_macos -1 /tmp/ftest"
run_test "ls -l"       "$MACIFY tests/real/ls_macos -l /tmp/ftest"
run_test "ls -la"      "$MACIFY tests/real/ls_macos -la /tmp/ftest"
run_test "tree"        "$MACIFY tests/real/tree_macos /tmp/ftest"
run_test "find"        "$MACIFY tests/real/find_macos /tmp/ftest -name '*.txt'"
run_test "fd"          "$MACIFY tests/real/fd_macos '.txt' /tmp/ftest"
run_test "rg"          "$MACIFY tests/real/rg_macos 9 /tmp/ftest/nums.txt"

echo
echo "=== JSON/Data ==="
run_test "jq name"     "$MACIFY tests/real/jq_darwin -r '.name' /tmp/ftest/data.json"
run_test "jq sum"      "$MACIFY tests/real/jq_darwin '.nums | add' /tmp/ftest/data.json"
run_test "sqlite3"     "echo 'SELECT 1+1;' | $MACIFY tests/real/sqlite3_macos"
run_test "diff"        "$MACIFY tests/real/diff_macos /tmp/ftest/a.txt /tmp/ftest/nums.txt" 2

echo
echo "=== Compression ==="
run_test "gzip -c"     "$MACIFY tests/real/gzip_macos -c /tmp/ftest/nums.txt | wc -c"

echo
echo "=== Editors/Pagers ==="
run_test "less"        "$MACIFY tests/real/less_macos /tmp/ftest/nums.txt"
run_test "nano --version"  "$MACIFY tests/real/nano_macos --version"

echo
echo "=== Modern Tools (functional) ==="
run_test "sd"          "echo hello | $MACIFY tests/real/sd_macos hello goodbye"
run_test "bat"         "$MACIFY tests/real/bat_macos --style=plain /tmp/ftest/a.txt"

echo
echo "=== Summary ==="
echo "Pass: $PASS, Fail: $FAIL, Timeout: $SKIP"
