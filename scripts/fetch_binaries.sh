#!/bin/bash
# fetch_binaries.sh — download macOS x86_64 binaries for testing macify
#
# Sources:
#   - MacPorts (https://packages.macports.org/) — coreutils, diffutils,
#     grep, findutils, gsed, gawk, gzip, bzip2, xz, zstd, pigz, less,
#     nano, bc, binutils, gnutar, gmake, file, texinfo
#   - GitHub releases — watchexec, btm
#
# Usage: ./scripts/fetch_binaries.sh
#
# Idempotent: skips binaries already present in tests/real/.
# Optional: set GITHUB_TOKEN for higher GitHub API rate limits.
#
# Requires: curl, tar, bzip2, xz, python3 (and unzip for .zip assets).

set -e

# ── Setup ────────────────────────────────────────────────────────
cd "$(dirname "$0")/.."
DEST_DIR="tests/real"
mkdir -p "$DEST_DIR"

# Unique temp dir per run; cleaned up on exit (even on error).
TMPDIR_FETCH="/tmp/macify-fetch-$$"
mkdir -p "$TMPDIR_FETCH"
trap 'rm -rf "$TMPDIR_FETCH"' EXIT

# Counters for end-of-run summary.
OK_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

status_ok()   { echo "  [OK]   $1"; OK_COUNT=$((OK_COUNT + 1)); }
status_fail() { echo "  [FAIL] $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
status_skip() { echo "  [SKIP] $1 (already exists)"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

# ── Helper: fetch a single binary from a MacPorts .tbz2 ──────────
# Usage: fetch_macports <name> <url> <binary_path_in_archive> <dest_filename>
#   name                   — human-readable label (e.g. "diffutils/gdiff")
#   url                    — full URL to the .tbz2 archive
#   binary_path_in_archive — path inside the archive (e.g. "opt/local/bin/gdiff")
#   dest_filename          — output filename in tests/real/ (e.g. "diff_macos")
fetch_macports() {
    local name="$1"
    local url="$2"
    local bin_path="$3"
    local dest="$4"

    local dest_path="$DEST_DIR/$dest"
    if [ -f "$dest_path" ] && [ -s "$dest_path" ]; then
        status_skip "$name"
        return 0
    fi

    echo "  [fetch] $name"
    local archive="$TMPDIR_FETCH/$(basename "$url")"
    local extract_dir="$TMPDIR_FETCH/${dest}.d"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"

    if ! curl -fsSL "$url" -o "$archive" 2>/dev/null; then
        status_fail "$name (download failed)"
        return 0
    fi

    if ! tar xjf "$archive" -C "$extract_dir" 2>/dev/null; then
        status_fail "$name (extraction failed)"
        return 0
    fi

    local src="$extract_dir/$bin_path"
    if [ -f "$src" ]; then
        if cp "$src" "$dest_path" && chmod +x "$dest_path"; then
            status_ok "$name -> $dest"
        else
            status_fail "$name (copy failed)"
        fi
    else
        status_fail "$name (binary not found at $bin_path)"
    fi
}

# ── Helper: fetch ALL g-prefixed binaries from a coreutils .tbz2 ─
# Usage: fetch_coreutils <url>
# Iterates over opt/local/bin/g* in the archive and writes each as
# <basename-without-leading-g>_macos (e.g. gcat -> cat_macos,
# gsort -> sort_macos). Downloads the archive only once per run.
fetch_coreutils() {
    local url="$1"
    local archive="$TMPDIR_FETCH/coreutils.tbz2"
    local extract_dir="$TMPDIR_FETCH/coreutils.d"

    if [ ! -d "$extract_dir" ]; then
        rm -rf "$extract_dir"
        mkdir -p "$extract_dir"
        echo "  [fetch] coreutils (one-time archive download)"
        if ! curl -fsSL "$url" -o "$archive" 2>/dev/null; then
            status_fail "coreutils (download failed)"
            return 0
        fi
        if ! tar xjf "$archive" -C "$extract_dir" 2>/dev/null; then
            status_fail "coreutils (extraction failed)"
            return 0
        fi
    fi

    local bin_dir="$extract_dir/opt/local/bin"
    if [ ! -d "$bin_dir" ]; then
        status_fail "coreutils (no opt/local/bin in archive)"
        return 0
    fi

    local gbin base stripped dest dest_path
    for gbin in "$bin_dir"/g*; do
        [ -f "$gbin" ] || continue
        base=$(basename "$gbin")
        stripped="${base#g}"            # gcat -> cat, gmd5sum -> md5sum
        dest="${stripped}_macos"
        dest_path="$DEST_DIR/$dest"
        if [ -f "$dest_path" ] && [ -s "$dest_path" ]; then
            status_skip "coreutils/$base"
        else
            if cp "$gbin" "$dest_path" && chmod +x "$dest_path"; then
                status_ok "coreutils/$base -> $dest"
            else
                status_fail "coreutils/$base (copy failed)"
            fi
        fi
    done
}

# ── Helper: fetch from GitHub releases (latest) ──────────────────
# Usage: fetch_gh <name> <repo> <asset_pattern> <dest_filename>
#   name          — human-readable label (also used as a binary-name hint)
#   repo          — owner/repo on GitHub (e.g. "watchexec/watchexec")
#   asset_pattern — substring to match in asset filename
#                   (e.g. "x86_64-apple-darwin")
#   dest_filename — output filename in tests/real/
#
# Uses $GITHUB_TOKEN for API auth if set. Handles .tar.gz, .tar.xz,
# .tar.bz2, and .zip archives. Locates the binary inside by trying
# (1) a file matching the repo's project name, (2) a file matching
# the friendly name, (3) the first executable found. Falls back to
# treating the download as a raw binary if extraction fails.
fetch_gh() {
    local name="$1"
    local repo="$2"
    local pattern="$3"
    local dest="$4"

    local dest_path="$DEST_DIR/$dest"
    if [ -f "$dest_path" ] && [ -s "$dest_path" ]; then
        status_skip "$name"
        return 0
    fi

    echo "  [fetch] $name from $repo"

    local auth_args=()
    if [ -n "$GITHUB_TOKEN" ]; then
        auth_args=(-H "Authorization: Bearer $GITHUB_TOKEN")
    fi

    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url
    download_url=$(curl -fsSL "${auth_args[@]}" "$api_url" 2>/dev/null \
        | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    pat = sys.argv[1] if len(sys.argv) > 1 else None
    for a in d.get("assets", []):
        if pat and pat in a["name"]:
            print(a["browser_download_url"])
            break
except Exception:
    pass
' "$pattern" 2>/dev/null || true)

    if [ -z "$download_url" ]; then
        status_fail "$name (no asset matching '$pattern')"
        return 0
    fi

    local archive="$TMPDIR_FETCH/${dest}.archive"
    local extract_dir="$TMPDIR_FETCH/${dest}.d"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"

    if ! curl -fsSL "${auth_args[@]}" "$download_url" -o "$archive" 2>/dev/null; then
        status_fail "$name (asset download failed)"
        return 0
    fi

    # Extract based on extension. Each branch ends with `|| true` so a
    # failing extraction doesn't trip `set -e`; we check $extracted below.
    local extracted=0
    case "$download_url" in
        *.tar.xz|*.txz)     tar xJf "$archive" -C "$extract_dir" 2>/dev/null && extracted=1 || true ;;
        *.tar.gz|*.tgz)     tar xzf  "$archive" -C "$extract_dir" 2>/dev/null && extracted=1 || true ;;
        *.tar.bz2|*.tbz2)   tar xjf  "$archive" -C "$extract_dir" 2>/dev/null && extracted=1 || true ;;
        *.zip)              if command -v unzip >/dev/null 2>&1; then
                                unzip -o "$archive" -d "$extract_dir" 2>/dev/null && extracted=1 || true
                            fi ;;
        *)                  tar xf   "$archive" -C "$extract_dir" 2>/dev/null && extracted=1 || true ;;
    esac

    if [ "$extracted" -ne 1 ]; then
        # Fall back to treating the download as a raw binary.
        if [ -s "$archive" ]; then
            if cp "$archive" "$dest_path" && chmod +x "$dest_path"; then
                status_ok "$name -> $dest (raw)"
            else
                status_fail "$name (raw copy failed)"
            fi
        else
            status_fail "$name (extraction failed and archive empty)"
        fi
        return 0
    fi

    # Locate the binary inside the extracted tree.
    local proj="${repo##*/}"
    local bin=""
    bin=$(find "$extract_dir" -type f -name "$proj" 2>/dev/null | head -1)
    if [ -z "$bin" ]; then
        bin=$(find "$extract_dir" -type f -name "$name" 2>/dev/null | head -1)
    fi
    if [ -z "$bin" ]; then
        while IFS= read -r f; do
            if [ -x "$f" ]; then
                bin="$f"
                break
            fi
        done < <(find "$extract_dir" -type f 2>/dev/null)
    fi

    if [ -n "$bin" ] && [ -f "$bin" ]; then
        if cp "$bin" "$dest_path" && chmod +x "$dest_path"; then
            status_ok "$name -> $dest"
        else
            status_fail "$name (copy failed)"
        fi
    else
        status_fail "$name (no binary in archive)"
    fi
}

# Wrap each fetch call so a single failure doesn't abort the whole run.
run() { "$@" || true; }

echo "=== Fetching macOS x86_64 test binaries ==="
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MacPorts  (https://packages.macports.org/)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo "-- MacPorts packages --"

MP="https://packages.macports.org"

# coreutils — all g-prefixed binaries (gcat->cat_macos, gsort->sort_macos, etc.)
run fetch_coreutils \
    "$MP/coreutils/coreutils-9.10_0.darwin_24.x86_64.tbz2"

# diffutils
run fetch_macports "diffutils/gdiff"  "$MP/diffutils/diffutils-3.12_0.darwin_24.x86_64.tbz2" "opt/local/bin/gdiff"  "diff_macos"
run fetch_macports "diffutils/gcmp"   "$MP/diffutils/diffutils-3.12_0.darwin_24.x86_64.tbz2" "opt/local/bin/gcmp"   "cmp_macos"
run fetch_macports "diffutils/gdiff3" "$MP/diffutils/diffutils-3.12_0.darwin_24.x86_64.tbz2" "opt/local/bin/gdiff3" "diff3_macos"
run fetch_macports "diffutils/gsdiff" "$MP/diffutils/diffutils-3.12_0.darwin_24.x86_64.tbz2" "opt/local/bin/gsdiff" "sdiff_macos"

# grep
run fetch_macports "grep/ggrep" \
    "$MP/grep/grep-3.12_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/ggrep" "grep_macos"

# findutils
run fetch_macports "findutils/gfind"   "$MP/findutils/findutils-4.10.0_0.darwin_24.x86_64.tbz2" "opt/local/bin/gfind"   "find_macos"
run fetch_macports "findutils/gxargs"  "$MP/findutils/findutils-4.10.0_0.darwin_24.x86_64.tbz2" "opt/local/bin/gxargs"  "xargs_macos"
run fetch_macports "findutils/glocate" "$MP/findutils/findutils-4.10.0_0.darwin_24.x86_64.tbz2" "opt/local/bin/glocate" "locate_macos"

# gsed
run fetch_macports "gsed" \
    "$MP/gsed/gsed-4.10_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/gsed" "sed_macos"

# gawk
run fetch_macports "gawk" \
    "$MP/gawk/gawk-5.4.0_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/gawk" "awk_macos"

# gzip
run fetch_macports "gzip" \
    "$MP/gzip/gzip-1.14_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/gzip" "gzip_macos"

# bzip2
run fetch_macports "bzip2" \
    "$MP/bzip2/bzip2-1.0.8_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/bzip2" "bzip2_macos"

# xz
run fetch_macports "xz" \
    "$MP/xz/xz-5.8.3_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/xz" "xz_macos"

# zstd
run fetch_macports "zstd" \
    "$MP/zstd/zstd-1.5.7_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/zstd" "zstd_macos"

# pigz
run fetch_macports "pigz" \
    "$MP/pigz/pigz-2.8_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/pigz" "pigz_macos"

# less
run fetch_macports "less" \
    "$MP/less/less-692_0+pcre.darwin_24.x86_64.tbz2" \
    "opt/local/bin/less" "less_macos"

# nano
run fetch_macports "nano" \
    "$MP/nano/nano-9.1_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/nano" "nano_macos"

# bc
run fetch_macports "bc" \
    "$MP/bc/bc-1.08.2_0+libedit.darwin_24.x86_64.tbz2" \
    "opt/local/bin/bc" "bc_macos"

# binutils
run fetch_macports "binutils/gstrings" "$MP/binutils/binutils-2.46.1_0.darwin_24.x86_64.tbz2" "opt/local/bin/gstrings" "strings_macos"
run fetch_macports "binutils/gobjdump"  "$MP/binutils/binutils-2.46.1_0.darwin_24.x86_64.tbz2" "opt/local/bin/gobjdump"  "objdump_macos"
run fetch_macports "binutils/greadelf"  "$MP/binutils/binutils-2.46.1_0.darwin_24.x86_64.tbz2" "opt/local/bin/greadelf"  "readelf_macos"
run fetch_macports "binutils/gnm"       "$MP/binutils/binutils-2.46.1_0.darwin_24.x86_64.tbz2" "opt/local/bin/gnm"       "nm_macos"
run fetch_macports "binutils/gstrip"    "$MP/binutils/binutils-2.46.1_0.darwin_24.x86_64.tbz2" "opt/local/bin/gstrip"    "strip_macos"
run fetch_macports "binutils/gar"       "$MP/binutils/binutils-2.46.1_0.darwin_24.x86_64.tbz2" "opt/local/bin/gar"       "ar_macos"

# gnutar
run fetch_macports "gnutar" \
    "$MP/gnutar/gnutar-1.35_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/gnutar" "tar_macos"

# gmake
run fetch_macports "gmake" \
    "$MP/gmake/gmake-4.4.1_1.darwin_24.x86_64.tbz2" \
    "opt/local/bin/gmake" "make_macos"

# file
run fetch_macports "file" \
    "$MP/file/file-5.48_0.darwin_24.x86_64.tbz2" \
    "opt/local/bin/file" "file_macos"

# texinfo
run fetch_macports "makeinfo" \
    "$MP/texinfo/texinfo-7.3_0+perl5_34.darwin_24.x86_64.tbz2" \
    "opt/local/bin/makeinfo" "makeinfo_macos"

# util-linux (for rev)
run fetch_macports "rev" \
    "$MP/util-linux/util-linux-2.41.3_0.darwin_19.x86_64.tbz2" \
    "opt/local/bin/rev" "rev_macos"

# sqlite3
run fetch_macports "sqlite3" \
    "$MP/sqlite3/sqlite3-3.51.2_0+universal.darwin_10.i386-x86_64.tbz2" \
    "opt/local/bin/sqlite3" "sqlite3_macos"

# MacPorts coreutils has gnucut, but it may not be in the g* glob
# Check if cut_macos exists, if not try gnucut
if [ ! -f "$DEST_DIR/cut_macos" ]; then
    run fetch_macports "coreutils/gnucut" \
        "$MP/coreutils/coreutils-9.10_0.darwin_24.x86_64.tbz2" \
        "opt/local/bin/gnucut" "cut_macos"
fi

echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GitHub Releases
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo "-- GitHub releases --"

run fetch_gh "watchexec" "watchexec/watchexec" "x86_64-apple-darwin" "watchexec_macos"
run fetch_gh "btm"       "ClementTsang/bottom" "x86_64-apple-darwin" "btm_macos"
run fetch_gh "bat"       "sharkdp/bat"         "x86_64-apple-darwin" "bat_macos"
# fd: latest release only has aarch64, use v10.3.0 for x86_64
fetch_gh_fd() {
    local dest="$DEST_DIR/fd_macos"
    if [ -f "$dest" ] && [ -s "$dest" ]; then return 0; fi
    echo "  [fetch] fd v10.3.0 (x86_64)"
    local url="https://github.com/sharkdp/fd/releases/download/v10.3.0/fd-v10.3.0-x86_64-apple-darwin.tar.gz"
    local archive="$TMPDIR_FETCH/fd.tar.gz"
    local extract_dir="$TMPDIR_FETCH/fd.d"
    rm -rf "$extract_dir"; mkdir -p "$extract_dir"
    if curl -fsSL "$url" -o "$archive" 2>/dev/null && tar xzf "$archive" -C "$extract_dir" 2>/dev/null; then
        local bin=$(find "$extract_dir" -type f -name "fd" | head -1)
        if [ -n "$bin" ] && cp "$bin" "$dest" && chmod +x "$dest"; then
            echo "  [OK]   fd -> fd_macos"
        else
            echo "  [FAIL] fd (binary not found)"
        fi
    else
        echo "  [FAIL] fd (download failed)"
    fi
}
run fetch_gh_fd
run fetch_gh "rg"        "BurntSushi/ripgrep"  "x86_64-apple-darwin" "rg_macos"
run fetch_gh "sd"        "chmln/sd"            "x86_64-apple-darwin" "sd_macos"
run fetch_gh "dust"      "bootandy/dust"       "x86_64-apple-darwin" "dust_macos"
run fetch_gh "starship"  "starship/starship"   "x86_64-apple-darwin" "starship_macos"
run fetch_gh "zoxide"    "ajeetdsouza/zoxide"  "x86_64-apple-darwin" "zoxide_macos"
run fetch_gh "procs"     "dalance/procs"       "x86_64-mac"          "procs_macos"
run fetch_gh "jq"        "jqlang/jq"           "macos-amd64"         "jq_darwin"
run fetch_gh "xsv"       "BurntSushi/xsv"      "x86_64-apple-darwin" "xsv_macos"
run fetch_gh "rclone"    "rclone/rclone"       "osx-amd64"           "rclone_macos"
run fetch_gh "nvim"      "neovim/neovim"       "macos-x86_64"        "nvim_macos"

echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Homebrew bottles (more macOS binaries)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo "-- Homebrew bottles --"

# fetch_brew <name> <bottle_url> <bin_path_in_tar.gz> <dest>
# Uses Homebrew's formulae API to get bottle download URLs.
fetch_brew() {
    local name="$1"
    local formula="$2"
    local bin_path="$3"
    local dest="$4"
    local dest_path="$DEST_DIR/$dest"

    if [ -f "$dest_path" ] && [ -s "$dest_path" ]; then
        status_skip "$name"
        return 0
    fi

    echo "  [fetch] $name (brew)"
    local extract_dir="$TMPDIR_FETCH/${dest}.d"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"

    # Get bottle URL from Homebrew API
    local bottle_url
    bottle_url=$(curl -fsSL "https://formulae.brew.sh/api/formula/${formula}.json" 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    files = d.get("bottle", {}).get("stable", {}).get("files", {})
    # Try sonoma, ventura, monterey, big_sur, catalina (x86_64 only)
    for key in ["sonoma", "ventura", "monterey", "big_sur", "catalina"]:
        if key in files:
            print(files[key]["url"])
            break
    else:
        # Just get the first one
        for k, v in files.items():
            print(v["url"])
            break
except Exception:
    pass
' 2>/dev/null || true)

    if [ -z "$bottle_url" ]; then
        status_fail "$name (no bottle URL)"
        return 0
    fi

    local archive="$TMPDIR_FETCH/${dest}.tar.gz"
    # GHCR requires auth token for bottle downloads
    # URL format: https://ghcr.io/v2/homebrew/core/<name>/blobs/sha256:<hash>
    # Scope: repository:homebrew/core/<name>:pull
    local token
    token=$(curl -fsSL "https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/${formula}:pull" 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
    if [ -n "$token" ]; then
        if ! curl -fsSL -H "Authorization: Bearer $token" "$bottle_url" -o "$archive" 2>/dev/null; then
            status_fail "$name (download failed with token)"
            return 0
        fi
    else
        if ! curl -fsSL "$bottle_url" -o "$archive" 2>/dev/null; then
            status_fail "$name (download failed, no token)"
            return 0
        fi
    fi

    if ! tar xzf "$archive" -C "$extract_dir" 2>/dev/null; then
        status_fail "$name (extraction failed)"
        return 0
    fi

    local src="$extract_dir/$bin_path"
    if [ -f "$src" ]; then
        if cp "$src" "$dest_path" && chmod +x "$dest_path"; then
            status_ok "$name -> $dest"
        else
            status_fail "$name (copy failed)"
        fi
    else
        src=$(find "$extract_dir" -type f -name "$name" 2>/dev/null | head -1)
        if [ -n "$src" ] && [ -f "$src" ]; then
            if cp "$src" "$dest_path" && chmod +x "$dest_path"; then
                status_ok "$name -> $dest"
            else
                status_fail "$name (copy failed)"
            fi
        else
            status_fail "$name (binary not found)"
        fi
    fi
}

# wget
run fetch_brew "wget" "wget" "bin/wget" "wget_macos"
# htop
run fetch_brew "htop" "htop" "bin/htop" "htop_macos"
# tree
run fetch_brew "tree" "tree" "bin/tree" "tree_macos"
# curl
run fetch_brew "curl" "curl" "bin/curl" "curl_macos"

echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Summary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOTAL_OPS=$((OK_COUNT + FAIL_COUNT + SKIP_COUNT))
TOTAL_FILES=$(ls -1 "$DEST_DIR" 2>/dev/null | wc -l | tr -d ' ')

echo "=== Summary ==="
echo "  OK:     $OK_COUNT"
echo "  FAIL:   $FAIL_COUNT"
echo "  SKIP:   $SKIP_COUNT"
echo "  TOTAL:  $TOTAL_OPS operations"
echo ""
echo "Binaries in $DEST_DIR/: $TOTAL_FILES files"

exit 0
