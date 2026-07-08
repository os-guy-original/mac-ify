#!/bin/bash
# fetch_binaries.sh — download macOS x86_64 test binaries for mac-ify
#
# Usage: ./scripts/fetch_binaries.sh [pattern]
#   With no args, fetches all binaries.
#   With a pattern arg, only fetches binaries matching the pattern.
#
# Sources:
#   - GitHub releases (jq, rg, bat, hyperfine, sd, xsv, dust, starship, zoxide, neovim, hugo)
#   - GitHub specific tag (fd — latest dropped x86_64)
#   - static-curl (curl)
#   - MacPorts (wget, sqlite3, htop, tree)
#   - procs uses "x86_64-mac" not "x86_64-apple-darwin"

set -e
cd "$(dirname "$0")/.."
mkdir -p tests/real
cd tests/real

PATTERN="${1:-}"
TMPDIR="/tmp/macify-fetch"
mkdir -p "$TMPDIR"

echo "=== Fetching macOS x86_64 test binaries ==="

# ── Helper: extract archive and copy binary ────────────────────
extract_and_copy() {
    local name="$1" archive="$2" dest="$3" binname="$4"
    local filetype=$(file -b "$archive" | head -c 20)
    if echo "$filetype" | grep -qi "gzip\|tar\|zip\|bzip\|XZ"; then
        local extract_dir="$TMPDIR/${dest}"
        rm -rf "$extract_dir"
        mkdir -p "$extract_dir"
        # Try different archive formats
        tar xzf "$archive" -C "$extract_dir" 2>/dev/null || \
        tar xf "$archive" -C "$extract_dir" 2>/dev/null || \
        tar xJf "$archive" -C "$extract_dir" 2>/dev/null || \
        unzip -o "$archive" -d "$extract_dir" 2>/dev/null || \
        bunzip2 -k -c "$archive" | tar xf - -C "$extract_dir" 2>/dev/null || true
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

# ── Helper: download URL, extract, copy ────────────────────────
fetch_url() {
    local name="$1" url="$2" dest="$3" binname="$4"
    if [ -n "$PATTERN" ] && ! echo "$name $dest" | grep -qi "$PATTERN"; then return; fi
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists)"
        return
    fi
    echo "  [fetch] $name"
    local archive="$TMPDIR/${dest}.archive"
    if ! curl -sL "$url" -o "$archive" 2>/dev/null || [ ! -s "$archive" ]; then
        echo "  [FAIL] $name"
        return
    fi
    extract_and_copy "$name" "$archive" "$dest" "$binname"
}

# ── Helper: fetch from GitHub latest release via API ───────────
fetch_gh() {
    local name="$1" repo="$2" asset_pattern="$3" dest="$4" binname="$5"
    if [ -n "$PATTERN" ] && ! echo "$name $dest" | grep -qi "$PATTERN"; then return; fi
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists)"
        return
    fi
    echo "  [fetch] $name from $repo"
    local download_url=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null | \
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
        echo "  [WARN] No asset matching '$asset_pattern'"
        return
    fi
    local archive="$TMPDIR/${dest}.archive"
    curl -sL "$download_url" -o "$archive" 2>/dev/null
    extract_and_copy "$name" "$archive" "$dest" "$binname"
}

# ── Helper: fetch from specific GitHub release tag ─────────────
fetch_gh_tag() {
    local name="$1" repo="$2" tag="$3" asset_pattern="$4" dest="$5" binname="$6"
    if [ -n "$PATTERN" ] && ! echo "$name $dest" | grep -qi "$PATTERN"; then return; fi
    if [ -f "$dest" ] && [ -s "$dest" ]; then
        echo "  [skip] $name (already exists)"
        return
    fi
    echo "  [fetch] $name from $repo (tag: $tag)"
    local download_url=$(curl -sL "https://api.github.com/repos/$repo/releases/tags/$tag" 2>/dev/null | \
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
        echo "  [WARN] No asset matching '$asset_pattern'"
        return
    fi
    local archive="$TMPDIR/${dest}.archive"
    curl -sL "$download_url" -o "$archive" 2>/dev/null
    extract_and_copy "$name" "$archive" "$dest" "$binname"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GitHub Releases (Rust/C/Go binaries)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fetch_gh     "jq"        "jqlang/jq"            "macos-amd64"          "jq_darwin"       "jq"
fetch_gh     "ripgrep"   "BurntSushi/ripgrep"   "x86_64-apple-darwin"  "rg_macos"        "rg"
fetch_gh_tag "fd"        "sharkdp/fd"           "v8.7.1"  "x86_64-apple-darwin"  "fd_macos"  "fd"
fetch_gh     "bat"       "sharkdp/bat"          "x86_64-apple-darwin"  "bat_macos"       "bat"
fetch_gh     "hyperfine" "sharkdp/hyperfine"    "x86_64-apple-darwin"  "hyperfine_macos" "hyperfine"
fetch_gh     "sd"        "chmln/sd"             "x86_64-apple-darwin"  "sd_macos"        "sd"
fetch_gh     "xsv"       "BurntSushi/xsv"       "x86_64-apple-darwin"  "xsv_macos"       "xsv"
fetch_gh     "procs"     "dalance/procs"        "x86_64-mac"           "procs_macos"     "procs"
fetch_gh     "dust"      "bootandy/dust"        "x86_64-apple-darwin"  "dust_macos"      "dust"
fetch_gh     "starship"  "starship/starship"    "x86_64-apple-darwin"  "starship_macos"  "starship"
fetch_gh     "zoxide"    "ajeetdsouza/zoxide"   "x86_64-apple-darwin"  "zoxide_macos"    "zoxide"
fetch_gh     "rclone"    "rclone/rclone"        "osx-amd64"            "rclone_macos"    "rclone"
fetch_gh     "neovim"    "neovim/neovim"        "macos-x86_64"         "nvim_macos"      "nvim"
fetch_gh     "hugo"      "gohugoio/hugo"        "darwin-universal"     "hugo_macos"      "hugo"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# static-curl (curl)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fetch_url "curl" \
    "https://github.com/stunnel/static-curl/releases/download/8.21.0/curl-macos-x86_64-8.21.0.tar.xz" \
    "curl_macos" "curl"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MacPorts (wget, sqlite3, htop, tree)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fetch_url "wget" \
    "https://packages.macports.org/wget/wget-1.25.0_1+gnutls.darwin_24.x86_64.tbz2" \
    "wget_macos" "wget"

fetch_url "sqlite3" \
    "https://packages.macports.org/sqlite3/sqlite3-3.51.2_0+universal.darwin_10.i386-x86_64.tbz2" \
    "sqlite3_macos" "sqlite3"

fetch_url "htop" \
    "https://packages.macports.org/htop/htop-3.5.0_0.darwin_19.x86_64.tbz2" \
    "htop_macos" "htop"

fetch_url "tree" \
    "https://packages.macports.org/tree/tree-2.3.2_0.darwin_10.x86_64.tbz2" \
    "tree_macos" "tree"

# ── Cleanup ──────────────────────────────────────────────────────
rm -rf "$TMPDIR"

echo ""
echo "=== Done ==="
echo "Binaries in tests/real/:"
ls -1 *macos* *darwin* 2>/dev/null | sed 's/^/  /' || echo "  (none found)"
