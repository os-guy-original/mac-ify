#!/bin/bash
# fetch_more_binaries.sh — download more macOS x86_64 binaries for testing
#
# These binaries stress different parts of mac-ify:
# - Rust binaries (different codegen patterns)
# - C binaries (different libc usage)
# - Go binaries (different runtime, goroutines)
# - Python/Ruby (interpreted languages)
# - Git (complex file I/O + network)
# - ffmpeg (multimedia, complex codecs)
# - vim/neovim (terminal, ncurses)
# - make/cmake (process spawning)
# - ssh/openssh (crypto, network)
# - gzip/tar (compression)

set -e
cd "$(dirname "$0")/.."
mkdir -p tests/real
cd tests/real

echo "=== Fetching more macOS x86_64 test binaries ==="

fetch_gh() {
    local name="$1"
    local repo="$2"
    local pattern="$3"
    local dest_dir="$4"
    if [ -d "$dest_dir" ] || [ -f "$dest_dir" ]; then
        echo "  [skip] $name (already exists)"
        return
    fi
    echo "  [fetch] $name from $repo"
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -sL "$api_url" 2>/dev/null | grep "browser_download_url" | grep "$pattern" | head -1 | sed 's/.*"browser_download_url": *"//;s/".*//')
    if [ -n "$download_url" ]; then
        mkdir -p "/tmp/macify-fetch"
        local archive="/tmp/macify-fetch/${name}.tar.gz"
        curl -sL "$download_url" -o "$archive" || { echo "  [FAIL] $name"; return; }
        # Extract and find the binary
        local extract_dir="/tmp/macify-fetch/${name}"
        mkdir -p "$extract_dir"
        tar xzf "$archive" -C "$extract_dir" 2>/dev/null || true
        # Try tar without gzip
        tar xf "$archive" -C "$extract_dir" 2>/dev/null || true
        # Find the main binary
        local bin=$(find "$extract_dir" -type f -name "$name" 2>/dev/null | head -1)
        if [ -n "$bin" ] && [ -f "$bin" ]; then
            cp "$bin" "${name}_macos"
            echo "  [ok] $name -> ${name}_macos"
        else
            # Try unzipping (for .zip archives)
            local zip_archive="/tmp/macify-fetch/${name}.zip"
            if curl -sL "$download_url" -o "$zip_archive" 2>/dev/null; then
                unzip -o "$zip_archive" -d "$extract_dir" 2>/dev/null || true
                bin=$(find "$extract_dir" -type f -name "$name" 2>/dev/null | head -1)
                if [ -n "$bin" ] && [ -f "$bin" ]; then
                    cp "$bin" "${name}_macos"
                    echo "  [ok] $name -> ${name}_macos"
                else
                    echo "  [WARN] Could not find $name binary in archive"
                fi
            fi
        fi
    else
        echo "  [WARN] Could not find download URL for $name (pattern: $pattern)"
    fi
}

# ── Rust binaries ──────────────────────────────────────────
# These use different Rust codegen and may expose different issues

# eza (modern ls replacement, Rust)
fetch_gh "eza" "eza-community/eza" "x86_64-apple-darwin" "eza"

# delta (syntax-highlighting pager, Rust)
fetch_gh "delta" "dandavison/delta" "x86_64-apple-darwin" "delta"

# dust (du + rust, Rust)
fetch_gh "dust" "bootandy/dust" "x86_64-apple-darwin" "dust"

# tokei (count code, Rust)
fetch_gh "tokei" "XAMPPRocky/tokei" "x86_64-apple-darwin" "tokei"

# starship (shell prompt, Rust, uses lots of syscalls)
fetch_gh "starship" "starship/starship" "x86_64-apple-darwin" "starship"

# ripgrep-all (rg + file format support, Rust)
# fetch_gh "rga" "phiresky/ripgrep-all" "x86_64-apple-darwin" "rga"

# ── Go binaries ────────────────────────────────────────────
# Go has a completely different runtime (goroutines, own scheduler)

# caddy (web server, Go)
fetch_gh "caddy" "caddyserver/caddy" "darwin-amd64" "caddy"

# rclone (cloud storage, Go, lots of network)
fetch_gh "rclone" "rclone/rclone" "osx-amd64" "rclone"

# ── C/C++ binaries ─────────────────────────────────────────
# Different libc usage patterns

# neovim (text editor, C, heavy ncurses)
fetch_gh "nvim" "neovim/neovim" "macos-x86_64" "nvim"

# git (version control, C, complex file I/O + network)
fetch_gh "git" "git/git" "darwin" "git"
# Note: git doesn't provide macOS binaries on GitHub releases,
# we'll try fetching from git-scm.com instead

# ── Python/Ruby (interpreted) ──────────────────────────────
# These have their own runtime and may need many stubs

# python3 from python.org (universal2 binary)
echo "  [note] python3: download from python.org manually"

# ── Compression ────────────────────────────────────────────

# zstd (compression, C)
fetch_gh "zstd" "facebook/zstd" "darwin" "zstd"

# ── Network tools ──────────────────────────────────────────

# socat (network relay, C) — if available
# nmap (network scanner, C++) — too complex to build

# ── Shell utilities ────────────────────────────────────────

# fzf (fuzzy finder, Go)
fetch_gh "fzf" "junegunn/fzf" "darwin_amd64" "fzf"

# zoxide (directory jumper, Rust)
fetch_gh "zoxide" "ajeetdsouza/zoxide" "x86_64-apple-darwin" "zoxide"

# broot (tree + navigation, Rust)
fetch_gh "broot" "Canop/broot" "x86_64-apple-darwin" "broot"

# ── Dev tools ──────────────────────────────────────────────

# deno (JavaScript/TypeScript runtime, Rust/V8)
fetch_gh "deno" "denoland/deno" "x86_64-apple-darwin" "deno"

# rustup (Rust toolchain, Rust)
# fetch_gh "rustup" "rust-lang/rustup" "x86_64-apple-darwin" "rustup"

# ── Cleanup ────────────────────────────────────────────────
rm -rf /tmp/macify-fetch

echo ""
echo "=== Done ==="
echo "Binaries in tests/real/:"
ls -la *macos* *darwin* 2>/dev/null | awk '{print "  " $NF}'
