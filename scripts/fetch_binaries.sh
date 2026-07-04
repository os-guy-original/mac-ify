#!/bin/bash
# fetch_binaries.sh — download macOS x86_64 test binaries for mac-ify
#
# Usage: ./scripts/fetch_binaries.sh [pattern]
#   With no args, fetches all binaries.
#   With a pattern arg, only fetches binaries matching the pattern.
#
# Binaries are placed in tests/real/ and are NOT pushed to git (.gitignore).

set -e
cd "$(dirname "$0")/.."
mkdir -p tests/real
cd tests/real

PATTERN="${1:-}"
TMPDIR="/tmp/macify-fetch"
mkdir -p "$TMPDIR"

echo "=== Fetching macOS x86_64 test binaries ==="

# ── Helper: fetch a direct URL and extract the binary ──────────
fetch_url() {
    local name="$1"        # display name
    local url="$2"         # direct download URL
    local dest="$3"        # destination filename
    local binname="$4"     # name of binary inside archive

    if [ -n "$PATTERN" ] && ! echo "$name $dest" | grep -qi "$PATTERN"; then
        return
    fi
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists as $dest)"
        return
    fi

    echo "  [fetch] $name"
    local archive="$TMPDIR/${dest}.archive"
    if ! curl -sL "$url" -o "$archive" 2>/dev/null || [ ! -s "$archive" ]; then
        echo "  [FAIL] $name download failed"
        return
    fi

    # Check if it's an archive or a raw binary
    local filetype=$(file -b "$archive" | head -c 20)
    if echo "$filetype" | grep -qi "gzip\|tar\|zip"; then
        local extract_dir="$TMPDIR/${dest}"
        rm -rf "$extract_dir"
        mkdir -p "$extract_dir"
        tar xzf "$archive" -C "$extract_dir" 2>/dev/null || \
        tar xf "$archive" -C "$extract_dir" 2>/dev/null || \
        unzip -o "$archive" -d "$extract_dir" 2>/dev/null || true

        local bin=$(find "$extract_dir" -type f -name "$binname" 2>/dev/null | head -1)
        if [ -n "$bin" ] && [ -f "$bin" ]; then
            cp "$bin" "$dest"
            echo "  [ok] $name -> $dest"
        else
            echo "  [WARN] Could not find '$binname' in archive for $name"
        fi
    else
        # Raw binary — just copy
        cp "$archive" "$dest"
        chmod +x "$dest"
        echo "  [ok] $name -> $dest"
    fi
}

# ── Helper: fetch from GitHub latest release ───────────────────
# Uses the GitHub API to find the latest release tag, then constructs
# the download URL. This handles versioned asset names (e.g. fd-v10.4.2-...)
fetch_gh() {
    local name="$1"
    local repo="$2"
    local asset_pattern="$3"   # pattern to match asset name
    local dest="$4"
    local binname="$5"

    if [ -n "$PATTERN" ] && ! echo "$name $dest" | grep -qi "$PATTERN"; then
        return
    fi
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists as $dest)"
        return
    fi

    echo "  [fetch] $name from $repo"
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -sL "$api_url" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for a in d.get('assets', []):
        if '$asset_pattern' in a['name']:
            print(a['browser_download_url'])
            break
except: pass
" 2>/dev/null)

    if [ -z "$download_url" ]; then
        echo "  [WARN] Could not find asset matching '$asset_pattern' for $name"
        return
    fi

    local archive="$TMPDIR/${dest}.archive"
    if ! curl -sL "$download_url" -o "$archive" 2>/dev/null || [ ! -s "$archive" ]; then
        echo "  [FAIL] $name download failed"
        return
    fi

    local filetype=$(file -b "$archive" | head -c 20)
    if echo "$filetype" | grep -qi "gzip\|tar\|zip"; then
        local extract_dir="$TMPDIR/${dest}"
        rm -rf "$extract_dir"
        mkdir -p "$extract_dir"
        tar xzf "$archive" -C "$extract_dir" 2>/dev/null || \
        tar xf "$archive" -C "$extract_dir" 2>/dev/null || \
        unzip -o "$archive" -d "$extract_dir" 2>/dev/null || true

        local bin=$(find "$extract_dir" -type f -name "$binname" 2>/dev/null | head -1)
        if [ -n "$bin" ] && [ -f "$bin" ]; then
            cp "$bin" "$dest"
            echo "  [ok] $name -> $dest"
        else
            echo "  [WARN] Could not find '$binname' in archive for $name"
        fi
    else
        cp "$archive" "$dest"
        chmod +x "$dest"
        echo "  [ok] $name -> $dest"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Rust binaries
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# jq — raw binary, asset name: jq-macos-amd64
fetch_gh "jq"       "jqlang/jq"            "macos-amd64"         "jq_darwin"       "jq"

# ripgrep — tar.gz, asset name: ripgrep-*-x86_64-apple-darwin
fetch_gh "ripgrep"  "BurntSushi/ripgrep"   "x86_64-apple-darwin" "rg_macos"        "rg"

# fd — tar.gz, asset name: fd-v*-x86_64-apple-darwin
fetch_gh "fd"       "sharkdp/fd"           "x86_64-apple-darwin" "fd_macos"        "fd"

# bat — tar.gz, asset name: bat-v*-x86_64-apple-darwin
fetch_gh "bat"      "sharkdp/bat"          "x86_64-apple-darwin" "bat_macos"       "bat"

# hyperfine — tar.gz
fetch_gh "hyperfine" "sharkdp/hyperfine"   "x86_64-apple-darwin" "hyperfine_macos" "hyperfine"

# sd — tar.gz
fetch_gh "sd"       "chmln/sd"             "x86_64-apple-darwin" "sd_macos"        "sd"

# xsv — tar.gz
fetch_gh "xsv"      "BurntSushi/xsv"       "x86_64-apple-darwin" "xsv_macos"       "xsv"

# procs — tar.gz, asset name: procs-v*-x86_64-apple-darwin
fetch_gh "procs"    "dalance/procs"        "x86_64-apple-darwin" "procs_macos"     "procs"

# dust — tar.gz
fetch_gh "dust"     "bootandy/dust"        "x86_64-apple-darwin" "dust_macos"      "dust"

# starship — tar.gz
fetch_gh "starship" "starship/starship"    "x86_64-apple-darwin" "starship_macos"  "starship"

# zoxide — tar.gz
fetch_gh "zoxide"   "ajeetdsouza/zoxide"   "x86_64-apple-darwin" "zoxide_macos"    "zoxide"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Go binaries
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# rclone — zip, asset name: rclone-*-osx-amd64.zip
fetch_gh "rclone"   "rclone/rclone"        "osx-amd64"           "rclone_macos"    "rclone"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# C/C++ binaries
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# neovim — tar.gz
fetch_gh "neovim"   "neovim/neovim"        "macos-x86_64"        "nvim_macos"      "nvim"

# hugo — .pkg (extract with xar + cpio) or extended tar.gz
fetch_gh "hugo"     "gohugoio/hugo"        "darwin-universal"    "hugo_macos"      "hugo"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Binaries fetched from other sources (not GitHub releases)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# curl — from Homebrew bottles (macOS x86_64)
# Homebrew bottles are at: https://ghcr.io/v2/homebrew/core/curl/blobs/
# But that requires auth. Instead, we can get curl from the curl project's
# own macOS builds, or just note that the user should provide it.
if [ -f "curl_macos" ] && [ -s "curl_macos" ]; then
    echo "  [skip] curl (already exists as curl_macos)"
else
    echo "  [note] curl_macos: download from https://curl.se/dlwiz/?type=bin&os=MacOSX"
fi

# wget — from macos binaries
if [ -f "wget_macos" ] && [ -s "wget_macos" ]; then
    echo "  [skip] wget (already exists as wget_macos)"
else
    echo "  [note] wget_macos: download from https://ftp.gnu.org/gnu/wget/ and build, or copy from macOS"
fi

# sqlite3 — from sqlite.org (sqlite-tools-macos-*.zip)
if [ -f "sqlite3_macos" ] && [ -s "sqlite3_macos" ]; then
    echo "  [skip] sqlite3 (already exists as sqlite3_macos)"
else
    echo "  [note] sqlite3_macos: download from https://sqlite.org/download.html (sqlite-tools-macos)"
fi

# htop — from htop-dev/htop releases (tarball, needs building) or Homebrew
if [ -f "htop_macos" ] && [ -s "htop_macos" ]; then
    echo "  [skip] htop (already exists as htop_macos)"
else
    echo "  [note] htop_macos: copy from macOS Homebrew or build from source"
fi

# tree — no pre-built macOS binary on GitHub; use Homebrew or build from source
if [ -f "tree_macos" ] && [ -s "tree_macos" ]; then
    echo "  [skip] tree (already exists as tree_macos)"
else
    echo "  [note] tree_macos: build from http://mama.indstate.edu/users/ice/tree/ or copy from macOS"
fi

# ── Cleanup ──────────────────────────────────────────────────────
rm -rf "$TMPDIR"

echo ""
echo "=== Done ==="
echo "Binaries in tests/real/:"
ls -1 *macos* *darwin* 2>/dev/null | sed 's/^/  /' || echo "  (none found)"
