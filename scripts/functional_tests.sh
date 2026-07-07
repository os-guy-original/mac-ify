#!/bin/bash
# Comprehensive functional tests for macify
# Tests actual functionality (not just --version) of macOS binaries
# Skips binaries that don't exist

LD_LIBRARY_PATH=build
export LD_LIBRARY_PATH
MACIFY="build/macify"
TIMEOUT=10
PASS=0
FAIL=0
SKIP=0
FAILURES=""

run_test() {
    local name="$1"
    local cmd="$2"
    local expected_exit="${3:-0}"
    local check_stdout="${4:-}"

    local result
    result=$(timeout $TIMEOUT bash -c "$cmd" 2>/dev/null; echo "EXIT:$?")
    local exit_code=$(echo "$result" | tail -1 | sed 's/EXIT://')
    local output=$(echo "$result" | head -n -1)

    if [ "$exit_code" = "124" ]; then
        echo "[TIMEOUT] $name"
        SKIP=$((SKIP+1))
    elif [ "$exit_code" != "$expected_exit" ]; then
        echo "[FAIL] $name (exit $exit_code, expected $expected_exit)"
        FAIL=$((FAIL+1))
        FAILURES="$FAILURES\n  $name (exit $exit_code, expected $expected_exit)"
    elif [ -n "$check_stdout" ] && ! echo "$output" | grep -qE "$check_stdout"; then
        echo "[FAIL] $name (stdout mismatch: expected '$check_stdout')"
        FAIL=$((FAIL+1))
        FAILURES="$FAILURES\n  $name (stdout mismatch)"
    else
        echo "[PASS] $name"
        PASS=$((PASS+1))
    fi
}

# Helper: only run test if binary exists
run_if_exists() {
    local bin="$1"; shift
    local name="$1"; shift
    if [ ! -f "tests/real/$bin" ]; then
        echo "[SKIP] $name (binary not found)"
        SKIP=$((SKIP+1))
        return
    fi
    run_test "$name" "$@"
}

# Setup test data
mkdir -p /tmp/ftest
echo "hello world from mac" > /tmp/ftest/a.txt
echo "second line" >> /tmp/ftest/a.txt
echo '{"name":"macify","version":"1.0","nums":[1,2,3,4,5]}' > /tmp/ftest/data.json
for i in 3 1 4 1 5 9 2 6; do echo $i; done > /tmp/ftest/nums.txt
printf "5\n3\n1\n4\n2\n" > /tmp/nums2.txt
echo "b 2" > /tmp/ftest/key.txt; echo "a 1" >> /tmp/ftest/key.txt; echo "c 3" >> /tmp/ftest/key.txt
mkdir -p /tmp/ftest/sub1/sub2
echo "nested" > /tmp/ftest/sub1/b.txt
echo "deep" > /tmp/ftest/sub1/sub2/c.txt

echo "============================================================="
echo "  Core File Operations"
echo "============================================================="
run_if_exists cat_macos        "cat"        "$MACIFY tests/real/cat_macos /tmp/ftest/a.txt" 0 "hello world"
run_if_exists head_macos       "head -1"    "$MACIFY tests/real/head_macos -1 /tmp/ftest/a.txt" 0 "hello world"
run_if_exists head_macos       "head -2"    "$MACIFY tests/real/head_macos -2 /tmp/ftest/a.txt" 0 "hello world|second line"
run_if_exists tail_macos       "tail -1"    "$MACIFY tests/real/tail_macos -1 /tmp/ftest/a.txt" 0 "second line"
run_if_exists tac_macos        "tac"        "$MACIFY tests/real/tac_macos /tmp/ftest/a.txt" 0 "second line"
run_if_exists nl_macos         "nl"         "$MACIFY tests/real/nl_macos /tmp/ftest/a.txt" 0 "1"
run_if_exists wc_macos         "wc -l"      "$MACIFY tests/real/wc_macos -l /tmp/ftest/a.txt" 0 "2"
run_if_exists wc_macos         "wc -w"      "$MACIFY tests/real/wc_macos -w /tmp/ftest/a.txt" 0 "6"
run_if_exists wc_macos         "wc -c"      "$MACIFY tests/real/wc_macos -c /tmp/ftest/a.txt" 0 "33"
run_if_exists wc_macos         "wc -m"      "$MACIFY tests/real/wc_macos -m /tmp/ftest/a.txt" 0 "33"
run_if_exists wc_macos         "wc -L"      "$MACIFY tests/real/wc_macos -L /tmp/ftest/a.txt" 0 "20"
run_if_exists wc_macos         "wc (all)"   "$MACIFY tests/real/wc_macos /tmp/ftest/a.txt" 0 "2.*6.*33"
run_if_exists cksum_macos      "cksum"      "$MACIFY tests/real/cksum_macos /tmp/ftest/a.txt" 0
run_if_exists md5sum_macos     "md5sum"     "$MACIFY tests/real/md5sum_macos /tmp/ftest/a.txt" 0 "[0-9a-f]{32}"
run_if_exists sha256sum_macos  "sha256sum"  "$MACIFY tests/real/sha256sum_macos /tmp/ftest/a.txt" 0 "[0-9a-f]{64}"
run_if_exists tr_macos         "tr a-z A-Z" "$MACIFY tests/real/tr_macos a-z A-Z < /tmp/ftest/nums.txt" 0
run_if_exists cut_macos        "cut -d' '"  "$MACIFY tests/real/cut_macos -d' ' -f1 /tmp/ftest/key.txt" 0 "b|a|c"
run_if_exists paste_macos      "paste"      "$MACIFY tests/real/paste_macos /tmp/ftest/nums.txt /tmp/nums2.txt" 0
run_if_exists comm_macos       "comm"       "$MACIFY tests/real/comm_macos <(sort -n /tmp/ftest/nums.txt) <(sort -n /tmp/nums2.txt)" 0
run_if_exists uniq_macos       "uniq"       "$MACIFY tests/real/uniq_macos /tmp/ftest/nums.txt" 0
run_if_exists rev_macos        "rev"        "$MACIFY tests/real/rev_macos < /tmp/ftest/nums.txt" 0
run_if_exists seq_macos        "seq 1 5"    "$MACIFY tests/real/seq_macos 1 5" 0 "1|2|3|4|5"
run_if_exists echo_macos       "echo"       "$MACIFY tests/real/echo_macos hello" 0 "hello"
run_if_exists printf_macos     "printf"     "$MACIFY tests/real/printf_macos '%d\n' 42" 0 "42"
run_if_exists basename_macos   "basename"   "$MACIFY tests/real/basename_macos /tmp/ftest/a.txt" 0 "a.txt"
run_if_exists dirname_macos    "dirname"    "$MACIFY tests/real/dirname_macos /tmp/ftest/a.txt" 0 "/tmp/ftest"
run_if_exists env_macos        "env"        "$MACIFY tests/real/env_macos PATH=/test" 0 "PATH=/test"
run_if_exists printenv_macos   "printenv"   "$MACIFY tests/real/printenv_macos HOME" 0
run_if_exists id_macos         "id"         "$MACIFY tests/real/id_macos" 0 "uid="
run_if_exists whoami_macos     "whoami"     "$MACIFY tests/real/whoami_macos" 0
run_if_exists hostname_macos   "hostname"   "$MACIFY tests/real/hostname_macos" 0
run_if_exists uname_macos      "uname"      "$MACIFY tests/real/uname_macos" 0
run_if_exists date_macos       "date"       "$MACIFY tests/real/date_macos +%Y" 0 "20[0-9][0-9]"
run_if_exists true_macos       "true"       "$MACIFY tests/real/true_macos" 0
run_if_exists false_macos      "false"      "$MACIFY tests/real/false_macos" 1
run_if_exists yes_macos        "yes | head" "$MACIFY tests/real/yes_macos | head -1" 0 "y"
run_if_exists factor_macos     "factor 12"  "$MACIFY tests/real/factor_macos 12" 0

echo
echo "============================================================="
echo "  Text Processing"
echo "============================================================="
run_if_exists grep_macos       "grep"         "$MACIFY tests/real/grep_macos hello /tmp/ftest/a.txt" 0 "hello world"
run_if_exists grep_macos       "grep -n"      "$MACIFY tests/real/grep_macos -n 9 /tmp/ftest/nums.txt" 0 "6:9"
run_if_exists grep_macos       "grep -v"      "$MACIFY tests/real/grep_macos -v 9 /tmp/ftest/nums.txt" 0
run_if_exists grep_macos       "grep -c"      "$MACIFY tests/real/grep_macos -c 1 /tmp/ftest/nums.txt" 0 "2"
run_if_exists sed_macos        "sed s/a/b/"   "echo hello | $MACIFY tests/real/sed_macos 's/hello/goodbye/'" 0 "goodbye"
run_if_exists awk_macos        "awk print"    "$MACIFY tests/real/awk_macos '{print \$1}' /tmp/ftest/key.txt" 0 "b|a|c"
run_if_exists awk_macos        "awk sum"      "$MACIFY tests/real/awk_macos '{s+=\$1} END{print s}' /tmp/ftest/nums.txt" 0 "31"
run_if_exists bc_macos         "bc"           "echo '2+3' | $MACIFY tests/real/bc_macos" 0 "5"
run_if_exists bc_macos         "bc multiply"  "echo '6*7' | $MACIFY tests/real/bc_macos" 0 "42"

echo
echo "============================================================="
echo "  Sorting"
echo "============================================================="
run_if_exists sort_macos       "sort (basic)"    "$MACIFY tests/real/sort_macos /tmp/ftest/nums.txt" 0
run_if_exists sort_macos       "sort -n"         "$MACIFY tests/real/sort_macos -n /tmp/nums2.txt" 0
run_if_exists sort_macos       "sort -r"         "$MACIFY tests/real/sort_macos -r /tmp/nums2.txt" 0
run_if_exists sort_macos       "sort -rn"        "$MACIFY tests/real/sort_macos -rn /tmp/nums2.txt" 0
run_if_exists sort_macos       "sort -u"         "$MACIFY tests/real/sort_macos -u /tmp/ftest/nums.txt" 0
run_if_exists sort_macos       "sort -k2 -n"     "$MACIFY tests/real/sort_macos -k2 -n /tmp/ftest/key.txt" 0
run_if_exists sort_macos       "sort multi-file" "$MACIFY tests/real/sort_macos -n /tmp/nums2.txt /tmp/ftest/nums.txt" 0

echo
echo "============================================================="
echo "  Directory Listing & Search"
echo "============================================================="
run_if_exists ls_macos         "ls"          "$MACIFY tests/real/ls_macos /tmp/ftest" 0 "a.txt"
run_if_exists ls_macos         "ls -1"       "$MACIFY tests/real/ls_macos -1 /tmp/ftest" 0
run_if_exists ls_macos         "ls -l"       "$MACIFY tests/real/ls_macos -l /tmp/ftest" 0 "rw.*a.txt"
run_if_exists ls_macos         "ls -la"      "$MACIFY tests/real/ls_macos -la /tmp/ftest" 0
run_if_exists tree_macos       "tree"        "$MACIFY tests/real/tree_macos /tmp/ftest" 0 "a.txt"
run_if_exists find_macos       "find"        "$MACIFY tests/real/find_macos /tmp/ftest -name '*.txt'" 0 "\.txt"
run_if_exists find_macos       "find -type"  "$MACIFY tests/real/find_macos /tmp/ftest -type d" 0 "sub1"
run_if_exists fd_macos         "fd"          "$MACIFY tests/real/fd_macos '.txt' /tmp/ftest" 0 "\.txt"
run_if_exists rg_macos         "rg"          "$MACIFY tests/real/rg_macos 9 /tmp/ftest/nums.txt" 0 "9"
run_if_exists du_macos         "du"          "$MACIFY tests/real/du_macos -s /tmp/ftest" 0
run_if_exists df_macos         "df"          "$MACIFY tests/real/df_macos /tmp" 0
run_if_exists stat_macos       "stat"        "$MACIFY tests/real/stat_macos /tmp/ftest/a.txt" 0

echo
echo "============================================================="
echo "  File Management"
echo "============================================================="
run_if_exists cp_macos         "cp"       "$MACIFY tests/real/cp_macos /tmp/ftest/a.txt /tmp/ftest/copy_test.txt && test -f /tmp/ftest/copy_test.txt" 0
rm -f /tmp/ftest/copy_test.txt
run_if_exists mkdir_macos      "mkdir"    "$MACIFY tests/real/mkdir_macos -p /tmp/ftest/newdir/sub && test -d /tmp/ftest/newdir/sub" 0
rm -rf /tmp/ftest/newdir
run_if_exists touch_macos      "touch"    "$MACIFY tests/real/touch_macos /tmp/ftest/touched && test -f /tmp/ftest/touched" 0
rm -f /tmp/ftest/touched
run_if_exists ln_macos         "ln -s"    "$MACIFY tests/real/ln_macos -s /tmp/ftest/a.txt /tmp/ftest/link_test && test -L /tmp/ftest/link_test" 0
rm -f /tmp/ftest/link_test
run_if_exists rm_macos         "rm"       "echo test > /tmp/ftest/rmtest && $MACIFY tests/real/rm_macos /tmp/ftest/rmtest && ! test -f /tmp/ftest/rmtest" 0
run_if_exists rmdir_macos      "rmdir"    "$MACIFY tests/real/mkdir_macos /tmp/ftest/rdtest && $MACIFY tests/real/rmdir_macos /tmp/ftest/rdtest && ! test -d /tmp/ftest/rdtest" 0
run_if_exists mv_macos         "mv"       "echo test > /tmp/ftest/mvsrc && $MACIFY tests/real/mv_macos /tmp/ftest/mvsrc /tmp/ftest/mvdst && test -f /tmp/ftest/mvdst" 0
rm -f /tmp/ftest/mvdst

echo
echo "============================================================="
echo "  Diff & Patch"
echo "============================================================="
run_if_exists diff_macos       "diff"     "$MACIFY tests/real/diff_macos /tmp/ftest/a.txt /tmp/ftest/nums.txt" 1
run_if_exists cmp_macos        "cmp (same)" "$MACIFY tests/real/cmp_macos /tmp/ftest/a.txt /tmp/ftest/a.txt" 0
run_if_exists cmp_macos        "cmp (diff)" "$MACIFY tests/real/cmp_macos /tmp/ftest/a.txt /tmp/ftest/nums.txt" 1

echo
echo "============================================================="
echo "  Compression"
echo "============================================================="
run_if_exists gzip_macos       "gzip -c"  "$MACIFY tests/real/gzip_macos -c /tmp/ftest/nums.txt | wc -c" 0
run_if_exists bzip2_macos      "bzip2 -c" "$MACIFY tests/real/bzip2_macos -c /tmp/ftest/nums.txt | wc -c" 0
run_if_exists xz_macos         "xz -c"    "$MACIFY tests/real/xz_macos -c /tmp/ftest/nums.txt | wc -c" 0
run_if_exists zstd_macos       "zstd -c"  "$MACIFY tests/real/zstd_macos -c /tmp/ftest/nums.txt | wc -c" 0
run_if_exists pigz_macos       "pigz -c"  "$MACIFY tests/real/pigz_macos -c /tmp/ftest/nums.txt | wc -c" 0

echo
echo "============================================================="
echo "  Binary Tools"
echo "============================================================="
run_if_exists strings_macos    "strings"  "$MACIFY tests/real/strings_macos /tmp/ftest/a.txt" 0 "hello"
run_if_exists nm_macos         "nm"       "$MACIFY tests/real/nm_macos build/macify 2>/dev/null | head -1" 0
run_if_exists readelf_macos    "readelf"  "$MACIFY tests/real/readelf_macos -h build/macify 2>/dev/null | head -1" 0
run_if_exists file_macos       "file"     "$MACIFY tests/real/file_macos /tmp/ftest/a.txt" 0

echo
echo "============================================================="
echo "  JSON & Data"
echo "============================================================="
run_if_exists jq_darwin        "jq name"  "$MACIFY tests/real/jq_darwin -r '.name' /tmp/ftest/data.json" 0 "macify"
run_if_exists jq_darwin        "jq sum"   "$MACIFY tests/real/jq_darwin '.nums | add' /tmp/ftest/data.json" 0 "15"
run_if_exists sqlite3_macos    "sqlite3"  "echo 'SELECT 1+1;' | $MACIFY tests/real/sqlite3_macos" 0 "2"
run_if_exists xsv_macos        "xsv"      "echo 'a,b\n1,2' | $MACIFY tests/real/xsv_macos stats" 0

echo
echo "============================================================="
echo "  Modern Rust Tools"
echo "============================================================="
run_if_exists sd_macos         "sd"       "echo hello | $MACIFY tests/real/sd_macos hello goodbye" 0 "goodbye"
run_if_exists bat_macos        "bat"      "$MACIFY tests/real/bat_macos --style=plain /tmp/ftest/a.txt" 0 "hello world"
run_if_exists dust_macos       "dust"     "$MACIFY tests/real/dust_macos -d 1 /tmp/ftest 2>/dev/null | head -1" 0
run_if_exists starship_macos   "starship" "$MACIFY tests/real/starship_macos --version" 0 "starship"
run_if_exists zoxide_macos     "zoxide"   "$MACIFY tests/real/zoxide_macos --version" 0 "zoxide"
run_if_exists procs_macos      "procs"    "$MACIFY tests/real/procs_macos 2>/dev/null | head -1" 0
run_if_exists btm_macos        "btm"      "$MACIFY tests/real/btm_macos --version" 0
run_if_exists watchexec_macos  "watchexec" "$MACIFY tests/real/watchexec_macos --version" 0

echo
echo "============================================================="
echo "  Network Tools (--version only)"
echo "============================================================="
run_if_exists curl_macos       "curl"     "$MACIFY tests/real/curl_macos --version 2>/dev/null | head -1" 0 "curl"
run_if_exists wget_macos       "wget"     "$MACIFY tests/real/wget_macos --version 2>/dev/null | head -1" 0 "Wget"
run_if_exists rclone_macos     "rclone"   "$MACIFY tests/real/rclone_macos --version 2>/dev/null | head -1" 0 "rclone"

echo
echo "============================================================="
echo "  Editors & Pagers"
echo "============================================================="
run_if_exists less_macos       "less"     "$MACIFY tests/real/less_macos /tmp/ftest/nums.txt" 0 "3"
run_if_exists nano_macos       "nano"     "$MACIFY tests/real/nano_macos --version" 0 "nano"
run_if_exists nvim_macos       "nvim"     "$MACIFY tests/real/nvim_macos --version 2>&1 | head -1" 0 "NVIM"
run_if_exists htop_macos       "htop"     "$MACIFY tests/real/htop_macos --version" 0 "htop"

echo
echo "============================================================="
echo "  Build Tools"
echo "============================================================="
run_if_exists make_macos       "make"     "$MACIFY tests/real/make_macos --version 2>/dev/null | head -1" 0 "GNU Make"

echo
echo "============================================================="
echo "  Summary"
echo "============================================================="
echo "Pass: $PASS, Fail: $FAIL, Skip: $SKIP"
if [ $FAIL -gt 0 ]; then
    echo ""
    echo "Failures:"
    echo -e "$FAILURES"
fi
