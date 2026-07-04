#!/bin/bash
# fetch_binaries.sh — download macOS x86_64 test binaries for mac-ify
#
# This script downloads pre-built macOS x86_64 binaries from GitHub releases.
# Binaries are placed in tests/real/ and are NOT pushed to git (.gitignore).
#
# Usage: ./scripts/fetch_binaries.sh [pattern]
#   With no args, fetches all binaries.
#   With a pattern arg, only fetches binaries matching the pattern.
#
# Categories:
#   rust    — Rust binaries (jq, rg, fd, bat, hyperfine, sd, xsv, procs, dust, starship, zoxide)
#   go      — Go binaries (rclone)
#   c       — C/C++ binaries (nvim, tree)
#   manual  — Binaries that must be copied from macOS (curl, wget, sqlite3, htop)

set -e
cd "$(dirname "$0")/.."
mkdir -p tests/real
cd tests/real

PATTERN="${1:-}"
TMPDIR="/tmp/macify-fetch"
mkdir -p "$TMPDIR"

echo "=== Fetching macOS x86_64 test binaries ==="

# ── Helper: download, extract, and find the main binary ──────────
fetch_gh() {
    local name="$1"        # display name
    local repo="$2"        # github repo (owner/repo)
    local pattern="$3"     # download URL pattern to match
    local dest="$4"        # destination filename (e.g. "rg_macos")
    local binname="$5"     # name of the binary inside the archive

    # Skip if pattern filter doesn't match
    if [ -n "$PATTERN" ] && ! echo "$name $dest $repo" | grep -qi "$PATTERN"; then
        return
    fi

    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists as $dest)"
        return
    fi

    echo "  [fetch] $name from $repo"
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -sL "$api_url" 2>/dev/null | \
        grep "browser_download_url" | grep "$pattern" | head -1 | \
        sed 's/.*"browser_download_url": *"//;s/".*//')

    if [ -z "$download_url" ]; then
        echo "  [WARN] Could not find download URL for $name (pattern: $pattern)"
        return
    fi

    local archive="$TMPDIR/${dest}.archive"
    curl -sL "$download_url" -o "$archive" 2>/dev/null || {
        echo "  [FAIL] $name download failed"
        return
    }

    # Extract
    local extract_dir="$TMPDIR/${dest}"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar xzf "$archive" -C "$extract_dir" 2>/dev/null || \
    tar xf "$archive" -C "$extract_dir" 2>/dev/null || \
    unzip -o "$archive" -d "$extract_dir" 2>/dev/null || true

    # Find the binary
    local bin=$(find "$extract_dir" -type f -name "$binname" 2>/dev/null | head -1)
    if [ -n "$bin" ] && [ -f "$bin" ]; then
        cp "$bin" "$dest"
        echo "  [ok] $name -> $dest"
    else
        echo "  [WARN] Could not find '$binname' binary in archive for $name"
    fi
}

# ── Rust binaries ────────────────────────────────────────────────
fetch_gh "jq"          "jqlang/jq"            "darwin-amd64"        "jq_darwin"     "jq"
fetch_gh "ripgrep"     "BurntSushi/ripgrep"   "x86_64-apple-darwin" "rg_macos"      "rg"
fetch_gh "fd"          "sharkdp/fd"           "x86_64-apple-darwin" "fd_macos"      "fd"
fetch_gh "bat"         "sharkdp/bat"          "x86_64-apple-darwin" "bat_macos"     "bat"
fetch_gh "hyperfine"   "sharkdp/hyperfine"    "x86_64-apple-darwin" "hyperfine_macos" "hyperfine"
fetch_gh "sd"          "chmln/sd"             "x86_64-apple-darwin" "sd_macos"      "sd"
fetch_gh "xsv"         "BurntSushi/xsv"       "x86_64-apple-darwin" "xsv_macos"     "xsv"
fetch_gh "procs"       "dalance/procs"        "x86_64-apple-darwin" "procs_macos"   "procs"
fetch_gh "dust"        "bootandy/dust"        "x86_64-apple-darwin" "dust_macos"    "dust"
fetch_gh "starship"    "starship/starship"    "x86_64-apple-darwin" "starship_macos" "starship"
fetch_gh "zoxide"      "ajeetdsouza/zoxide"   "x86_64-apple-darwin" "zoxide_macos"  "zoxide"

# ── Go binaries ──────────────────────────────────────────────────
fetch_gh "rclone"      "rclone/rclone"        "osx-amd64"           "rclone_macos"  "rclone"

# ── C/C++ binaries ───────────────────────────────────────────────
fetch_gh "neovim"      "neovim/neovim"        "macos-x86_64"        "nvim_macos"    "nvim"
fetch_gh "tree"        "Old-Man-Programmer/tree" "darwin"           "tree_macos"    "tree"
fetch_gh "hugo"        "gohugoio/hugo"        "darwin-universal"    "hugo_macos"    "hugo"

# ── Binaries that must be copied from macOS ──────────────────────
for manual_bin in curl_macos wget_macos sqlite3_macos htop_macos; do
    if [ -f "$manual_bin" ]; then
        echo "  [skip] $manual_bin (already exists)"
    else
        echo "  [note] $manual_bin: copy from macOS Homebrew or build from source"
    fi
done

# ── Cleanup ──────────────────────────────────────────────────────
rm -rf "$TMPDIR"

echo ""
echo "=== Done ==="
echo "Binaries in tests/real/:"
ls -1 *macos* *darwin* 2>/dev/null | sed 's/^/  /' || echo "  (none found)"
