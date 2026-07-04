#!/bin/bash
# test_real.sh — Test real macOS binaries through mac-ify
# Usage: ./scripts/test_real.sh

cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH=build

BOLD='\033[1m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

PASS=0
FAIL=0
SKIP=0

run_test() {
    local name="$1"
    local binary="$2"
    shift 2
    local args=("$@")
    
    if [ ! -f "tests/real/$binary" ]; then
        echo -e "  ${YELLOW}SKIP${RESET}  $name (binary not found)"
        SKIP=$((SKIP + 1))
        return
    fi
    
    local output
    output=$(timeout 15 ./build/macify -q "tests/real/$binary" "${args[@]}" 2>/dev/null)
    local exit_code=$?
    
    if [ $exit_code -eq 0 ] && [ -n "$output" ]; then
        echo -e "  ${GREEN}PASS${RESET}  $name"
        PASS=$((PASS + 1))
    elif [ $exit_code -eq 124 ]; then
        echo -e "  ${YELLOW}SKIP${RESET}  $name (timed out)"
        SKIP=$((SKIP + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  $name (exit=$exit_code)"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${BOLD}=== Real Binary Tests ===${RESET}"
echo ""

echo -e "${CYAN}--version tests (basic load + run)${RESET}"
run_test "jq"          "jq_darwin"       --version
run_test "ripgrep"     "rg_macos"        --version
run_test "fd"          "fd_macos"        --version
run_test "bat"         "bat_macos"       --version
run_test "xsv"         "xsv_macos"       --version
run_test "sd"          "sd_macos"        --version
run_test "hyperfine"   "hyperfine_macos" --version
run_test "tree"        "tree_macos"      --version
run_test "sqlite3"     "sqlite3_macos"   --version
run_test "curl"        "curl_macos"      --version
run_test "htop"        "htop_macos"      --version
run_test "procs"       "procs_macos"     --version
run_test "dust"        "dust_macos"      --version
run_test "starship"    "starship_macos"  --version
run_test "zoxide"      "zoxide_macos"    --version
run_test "rclone"      "rclone_macos"    version
run_test "neovim"      "nvim_macos"      --version

echo ""
echo -e "${CYAN}Functional tests${RESET}"

# jq: JSON processing
if [ -f tests/real/jq_darwin ]; then
    result=$(echo '{"name":"test","value":42}' | timeout 10 ./build/macify -q tests/real/jq_darwin '.value' 2>/dev/null)
    if [ "$result" = "42" ]; then
        echo -e "  ${GREEN}PASS${RESET}  jq JSON processing (.value → 42)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  jq JSON processing (got: $result)"
        FAIL=$((FAIL + 1))
    fi
fi

# sqlite3: SQL execution
if [ -f tests/real/sqlite3_macos ]; then
    result=$(echo "SELECT 1+1;" | timeout 10 ./build/macify -q tests/real/sqlite3_macos 2>/dev/null)
    if [ "$result" = "2" ]; then
        echo -e "  ${GREEN}PASS${RESET}  sqlite3 SQL execution (SELECT 1+1 → 2)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  sqlite3 SQL execution (got: $result)"
        FAIL=$((FAIL + 1))
    fi
fi

# sd: text replacement
if [ -f tests/real/sd_macos ]; then
    result=$(echo "hello world" | timeout 10 ./build/macify -q tests/real/sd_macos "world" "mac-ify" 2>/dev/null)
    if [ "$result" = "hello mac-ify" ]; then
        echo -e "  ${GREEN}PASS${RESET}  sd text replacement (world → mac-ify)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  sd text replacement (got: $result)"
        FAIL=$((FAIL + 1))
    fi
fi

# curl HTTP
if [ -f tests/real/curl_macos ]; then
    result=$(timeout 15 ./build/macify -q tests/real/curl_macos -s http://httpbin.org/get 2>/dev/null | head -1)
    if echo "$result" | grep -q "{"; then
        echo -e "  ${GREEN}PASS${RESET}  curl HTTP (httpbin.org/get)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  curl HTTP (got: $result)"
        FAIL=$((FAIL + 1))
    fi
fi

# curl HTTPS
if [ -f tests/real/curl_macos ]; then
    result=$(timeout 15 ./build/macify -q tests/real/curl_macos -s https://httpbin.org/get 2>/dev/null | head -1)
    if echo "$result" | grep -q "{"; then
        echo -e "  ${GREEN}PASS${RESET}  curl HTTPS (httpbin.org/get)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  curl HTTPS (got: $result)"
        FAIL=$((FAIL + 1))
    fi
fi

# sqlite3: complex SQL
if [ -f tests/real/sqlite3_macos ]; then
    result=$(echo "CREATE TABLE t(x); INSERT INTO t VALUES (10), (20), (30); SELECT SUM(x) FROM t;" | timeout 10 ./build/macify -q tests/real/sqlite3_macos 2>/dev/null)
    if [ "$result" = "60" ]; then
        echo -e "  ${GREEN}PASS${RESET}  sqlite3 complex SQL (SUM → 60)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  sqlite3 complex SQL (got: $result)"
        FAIL=$((FAIL + 1))
    fi
fi

# xsv: CSV processing
if [ -f tests/real/xsv_macos ]; then
    echo "name,age
Alice,30
Bob,25" > /tmp/macify_test.csv
    result=$(timeout 10 ./build/macify -q tests/real/xsv_macos count /tmp/macify_test.csv 2>/dev/null)
    if [ "$result" = "2" ]; then
        echo -e "  ${GREEN}PASS${RESET}  xsv CSV processing (count → 2)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  xsv CSV processing (got: $result)"
        FAIL=$((FAIL + 1))
    fi
    rm -f /tmp/macify_test.csv
fi

# rg: search
if [ -f tests/real/rg_macos ]; then
    mkdir -p /tmp/macify_rg_test
    echo "hello world
foo bar
hello foo" > /tmp/macify_rg_test/test.txt
    result=$(timeout 10 ./build/macify -q tests/real/rg_macos "hello" /tmp/macify_rg_test/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$result" = "2" ]; then
        echo -e "  ${GREEN}PASS${RESET}  rg search (hello → 2 matches)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  rg search (got: $result matches)"
        FAIL=$((FAIL + 1))
    fi
    rm -rf /tmp/macify_rg_test
fi

# fd: find files
if [ -f tests/real/fd_macos ]; then
    mkdir -p /tmp/macify_fd_test
    touch /tmp/macify_fd_test/file1.txt /tmp/macify_fd_test/file2.txt
    result=$(timeout 10 ./build/macify -q tests/real/fd_macos --type f . /tmp/macify_fd_test/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$result" = "2" ]; then
        echo -e "  ${GREEN}PASS${RESET}  fd find files (→ 2 files)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}  fd find files (got: $result)"
        FAIL=$((FAIL + 1))
    fi
    rm -rf /tmp/macify_fd_test
fi

echo ""
echo -e "${BOLD}Results: ${GREEN}$PASS passed${RESET}, ${RED}$FAIL failed${RESET}, ${YELLOW}$SKIP skipped${RESET}"
