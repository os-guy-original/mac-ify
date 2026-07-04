#!/bin/bash
# fetch_binaries.sh — download macOS x86_64 test binaries for mac-ify
#
# This script downloads pre-built macOS x86_64 binaries that we use
# to test mac-ify. These are NOT pushed to git (see .gitignore) to
# keep the repo small.
#
# Usage: ./scripts/fetch_binaries.sh
#
# Binaries are placed in tests/real/

set -e
cd "$(dirname "$0")/.."
mkdir -p tests/real
cd tests/real

echo "=== Fetching macOS x86_64 test binaries ==="

# Helper: download a file from a URL, show progress
fetch() {
    local name="$1"
    local url="$2"
    local dest="$3"
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists)"
        return
    fi
    echo "  [fetch] $name"
    curl -sL "$url" -o "$dest" || echo "  [WARN] Failed to fetch $name"
}

# Helper: download from GitHub releases
fetch_gh_release() {
    local name="$1"
    local repo="$2"
    local pattern="$3"
    local dest="$4"
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists)"
        return
    fi
    echo "  [fetch] $name from GitHub: $repo"
    # Get latest release info
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -sL "$api_url" | grep "browser_download_url" | grep "$pattern" | head -1 | sed 's/.*"browser_download_url": *"//;s/".*//')
    if [ -n "$download_url" ]; then
        curl -sL "$download_url" -o "$dest" || echo "  [WARN] Failed to fetch $name"
    else
        echo "  [WARN] Could not find download URL for $name"
    fi
}

# jq — from GitHub releases (jq-darwin-amd64)
fetch_gh_release "jq" "jqlang/jq" "darwin-amd64" "jq_darwin"

# curl — from macOS Homebrew/curl releases
echo "  [note] curl_macos: copy from a macOS system or Homebrew bottle"

# ripgrep — from GitHub releases (ripgrep-*-x86_64-apple-darwin.tar.gz)
fetch_gh_release "ripgrep" "BurntSushi/ripgrep" "x86_64-apple-darwin" "rg.tar.gz"
if [ -f "rg.tar.gz" ]; then
    tar xzf rg.tar.gz 2>/dev/null || true
    # Find the rg binary and copy it
    rg_bin=$(find . -name "rg" -type f 2>/dev/null | head -1)
    if [ -n "$rg_bin" ] && [ -f "$rg_bin" ]; then
        cp "$rg_bin" rg_macos
    fi
fi

# fd — from GitHub releases (fd-*-x86_64-apple-darwin)
fetch_gh_release "fd" "sharkdp/fd" "x86_64-apple-darwin" "fd.tar.gz"
if [ -f "fd.tar.gz" ]; then
    tar xzf fd.tar.gz 2>/dev/null || true
    fd_bin=$(find . -name "fd" -type f 2>/dev/null | head -1)
    if [ -n "$fd_bin" ] && [ -f "$fd_bin" ]; then
        cp "$fd_bin" fd_macos
    fi
fi

# bat — from GitHub releases (bat-*-x86_64-apple-darwin)
fetch_gh_release "bat" "sharkdp/bat" "x86_64-apple-darwin" "bat.tar.gz"
if [ -f "bat.tar.gz" ]; then
    tar xzf bat.tar.gz 2>/dev/null || true
    bat_bin=$(find . -name "bat" -type f 2>/dev/null | head -1)
    if [ -n "$bat_bin" ] && [ -f "$bat_bin" ]; then
        cp "$bat_bin" bat_macos
    fi
fi

# hyperfine — from GitHub releases (hyperfine-*-x86_64-apple-darwin)
fetch_gh_release "hyperfine" "sharkdp/hyperfine" "x86_64-apple-darwin" "hyperfine.tar.gz"
if [ -f "hyperfine.tar.gz" ]; then
    tar xzf hyperfine.tar.gz 2>/dev/null || true
    hf_bin=$(find . -name "hyperfine" -type f 2>/dev/null | head -1)
    if [ -n "$hf_bin" ] && [ -f "$hf_bin" ]; then
        cp "$hf_bin" hyperfine_macos
    fi
fi

# tree — from GitHub releases or other source
fetch_gh_release "tree" "Old-Man-Programmer/tree" "darwin" "tree_macos"

# sd — from GitHub releases (sd-*-x86_64-apple-darwin)
fetch_gh_release "sd" "chmln/sd" "x86_64-apple-darwin" "sd.tar.gz"
if [ -f "sd.tar.gz" ]; then
    tar xzf sd.tar.gz 2>/dev/null || true
    sd_bin=$(find . -name "sd" -type f 2>/dev/null | head -1)
    if [ -n "$sd_bin" ] && [ -f "$sd_bin" ]; then
        cp "$sd_bin" sd_macos
    fi
fi

# xsv — from GitHub releases
fetch_gh_release "xsv" "BurntSushi/xsv" "x86_64-apple-darwin" "xsv.tar.gz"
if [ -f "xsv.tar.gz" ]; then
    tar xzf xsv.tar.gz 2>/dev/null || true
    xsv_bin=$(find . -name "xsv" -type f 2>/dev/null | head -1)
    if [ -n "$xsv_bin" ] && [ -f "$xsv_bin" ]; then
        cp "$xsv_bin" xsv_macos
    fi
fi

# sqlite3 — from sqlite.org (macOS prebuilt)
echo "  [note] sqlite3_macos: download from https://sqlite.org/download.html (sqlite-tools-macos-*.zip)"

# htop — from htop-dev/htop releases or Homebrew
echo "  [note] htop_macos: build from source or copy from macOS Homebrew"

# wget — from GNU wget or Homebrew
echo "  [note] wget_macos: copy from macOS Homebrew or build from source"

# curl_macos — copy from macOS Homebrew
echo "  [note] curl_macos: copy from macOS Homebrew"

# grep, gawk, gzip, less, nano, findutils — from Homebrew/coreutils
echo "  [note] grep_macos, gawk_macos, gzip_macos, less_macos, nano_macos, findutils_macos:"
echo "         copy from macOS Homebrew or build from source"

# procs — from GitHub releases
fetch_gh_release "procs" "dalance/procs" "x86_64-apple-darwin" "procs.tar.gz"
if [ -f "procs.tar.gz" ]; then
    tar xzf procs.tar.gz 2>/dev/null || true
    procs_bin=$(find . -name "procs" -type f 2>/dev/null | head -1)
    if [ -n "$procs_bin" ] && [ -f "$procs_bin" ]; then
        cp "$procs_bin" procs_macos
    fi
fi

# hugo — from GitHub releases
fetch_gh_release "hugo" "gohugoio/hugo" "darwin-universal" "hugo.tar.gz"
if [ -f "hugo.tar.gz" ]; then
    tar xzf hugo.tar.gz 2>/dev/null || true
fi

echo ""
echo "=== Done ==="
echo "Note: Some binaries (curl, wget, sqlite3, htop, grep, gawk, gzip,"
echo "less, nano, findutils) must be copied from a macOS system or"
echo "built from source. See notes above."
echo ""
echo "Binaries in tests/real/:"
ls -la *macos* *darwin* 2>/dev/null || echo "  (none found)"
