/*
 * prefix.c — macOS filesystem prefix (like Wine's drive_c)
 *
 * Creates a virtual macOS filesystem at ~/.macify/ so macOS binaries
 * find their expected paths without messing with the real system.
 *
 * Structure:
 *   ~/.macify/
 *   ├── Library/
 *   │   ├── Caches/              # macOS-style cache dir (bat, etc.)
 *   │   ├── Preferences/         # macOS-style preferences
 *   │   └── Application Support/ # macOS-style app data
 *   ├── System/
 *   │   └── Library/
 *   │       ├── CoreServices/
 *   │       └── Frameworks/
 *   ├── usr/
 *   │   └── lib/                 # macOS-style lib (our custom implementations)
 *   └── etc/                     # macOS-specific config files
 *
 * Path translation:
 *   ~/Library/...        → ~/.macify/Library/...
 *   /Library/...         → ~/.macify/Library/...
 *   /System/Library/...  → ~/.macify/System/Library/...
 *   /usr/lib/...         → ~/.macify/usr/lib/...
 *
 * Paths NOT translated (pass through to real filesystem):
 *   /etc/, /tmp/, /var/, /dev/, /proc/, /usr/bin/, /usr/share/
 *   ~/ (except ~/Library/)
 *   Relative paths
 *
 * Paths hidden from macOS binaries (return ENOENT):
 *   ~/.config/bat/     (prevents bat from reading Linux config)
 *   ~/.cache/bat/      (prevents bat from using Linux cache)
 */

#include "macify.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/* The prefix root: ~/.macify */
static char macify_prefix[PATH_MAX] = "";
static size_t macify_prefix_len = 0;
static int macify_prefix_initialized = 0;

/* Get the prefix path (~/.macify) */
const char *macify_get_prefix(void) {
    if (macify_prefix_initialized) return macify_prefix;

    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    snprintf(macify_prefix, sizeof(macify_prefix), "%s/.macify", home);
    macify_prefix_len = strlen(macify_prefix);
    macify_prefix_initialized = 1;
    return macify_prefix;
}

/* Create a directory if it doesn't exist */
static void ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        mkdir(path, 0755);
    }
}
/* Initialize the prefix directory structure.
 * Called from main() before the macOS binary's main(). */
void macify_init_prefix(void) {
    const char *prefix = macify_get_prefix();
    if (!prefix || macify_prefix_len == 0) return;

    char path[PATH_MAX];

    /* Create prefix root */
    ensure_dir(prefix);

    /* Library/ */
    snprintf(path, sizeof(path), "%s/Library", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/Library/Caches", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/Library/Preferences", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/Library/Application Support", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/Library/Logs", prefix);
    ensure_dir(path);

    /* System/Library/ */
    snprintf(path, sizeof(path), "%s/System", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/System/Library", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/System/Library/CoreServices", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/System/Library/Frameworks", prefix);
    ensure_dir(path);

    /* usr/lib/ */
    snprintf(path, sizeof(path), "%s/usr", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/lib", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local/lib", prefix);
    ensure_dir(path);

    /* etc/ — macOS-specific config (not symlinked; we create our own) */
    snprintf(path, sizeof(path), "%s/etc", prefix);
    ensure_dir(path);

    /* Create ~/Library symlink → ~/.macify/Library
     * This makes ~/Library/Caches/bat work for macOS binaries */
    const char *home = getenv("HOME");
    if (home) {
        char home_library[PATH_MAX];
        snprintf(home_library, sizeof(home_library), "%s/Library", home);

        char prefix_library[PATH_MAX];
        snprintf(prefix_library, sizeof(prefix_library), "%s/Library", prefix);

        /* Only create symlink if ~/Library doesn't already exist */
        struct stat st;
        if (lstat(home_library, &st) != 0) {
            symlink(prefix_library, home_library);
        }
    }

    /* Write a marker file so we know the prefix is initialized */
    snprintf(path, sizeof(path), "%s/.macify_prefix", prefix);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "macify prefix v1\n");
        fclose(f);
    }

    if (getenv("MACIFY_VERBOSE") || getenv("MACIFY_PREFIX_DEBUG")) {
        fprintf(stderr, "macify: prefix initialized at %s\n", prefix);
    }
}

/* Translate a macOS path to a prefix path.
 *
 * Returns:
 *   0  — path translated, result in `out`
 *   -1 — path should NOT be translated (pass through to real filesystem)
 *
 * Translation rules:
 *   ~/Library/...        → ~/.macify/Library/...
 *   /Library/...         → ~/.macify/Library/...
 *   /System/Library/...  → ~/.macify/System/Library/...
 *   /usr/lib/...         → ~/.macify/usr/lib/...
 *   /usr/local/lib/...   → ~/.macify/usr/local/lib/...
 */
int macify_translate_path(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) return -1;

    const char *prefix = macify_get_prefix();
    if (!prefix || macify_prefix_len == 0) return -1;

    const char *home = getenv("HOME");
    size_t home_len = home ? strlen(home) : 0;

    /* ~/Library/... → ~/.macify/Library/... */
    if (home && strncmp(path, home, home_len) == 0 && path[home_len] == '/') {
        if (strncmp(path + home_len + 1, "Library/", 8) == 0 ||
            strcmp(path + home_len + 1, "Library") == 0) {
            snprintf(out, out_size, "%s%s", prefix, path + home_len);
            return 0;
        }
        /* ~/... (not Library) — pass through */
        return -1;
    }

    /* /Library/... → ~/.macify/Library/... */
    if (strncmp(path, "/Library/", 9) == 0 || strcmp(path, "/Library") == 0) {
        snprintf(out, out_size, "%s%s", prefix, path);
        return 0;
    }

    /* /System/Library/... → ~/.macify/System/Library/... */
    if (strncmp(path, "/System/Library/", 16) == 0 || strcmp(path, "/System/Library") == 0) {
        snprintf(out, out_size, "%s%s", prefix, path);
        return 0;
    }

    /* /System/... (non-Library) → pass through (e.g., /System/Installation) */
    if (strncmp(path, "/System/", 8) == 0) {
        return -1;
    }

    /* /usr/lib/... → pass through (Go's runtime uses this for dylib loading,
     * and our shim already resolves macOS dylib paths to our .so) */
    if (strncmp(path, "/usr/lib/", 9) == 0 || strcmp(path, "/usr/lib") == 0) {
        return -1;
    }

    /* /usr/local/... → pass through */
    if (strncmp(path, "/usr/local/", 11) == 0) {
        return -1;
    }

    /* /private/... → pass through (macOS /private maps to Linux /var etc.) */
    if (strncmp(path, "/private/", 9) == 0) {
        return -1;
    }

    /* Everything else: pass through */
    return -1;
}

/* Check if a path should be hidden from macOS binaries.
 *
 * Returns 1 if the path should return ENOENT, 0 otherwise.
 *
 * Hidden paths:
 *   ~/.config/bat/     (prevents bat from reading Linux config)
 *   ~/.cache/bat/      (prevents bat from using Linux cache)
 *   ~/.config/rclone/  (prevents rclone from reading Linux config)
 */
int macify_should_hide_path(const char *path) {
    if (!path) return 0;

    const char *home = getenv("HOME");
    if (!home) return 0;

    size_t home_len = strlen(home);
    if (strncmp(path, home, home_len) != 0 || path[home_len] != '/') {
        return 0;
    }

    const char *rest = path + home_len + 1;

    /* Hide ~/.config/bat/ — bat should use ~/Library/Caches/bat instead */
    if (strncmp(rest, ".config/bat", 11) == 0 &&
        (rest[11] == '\0' || rest[11] == '/')) {
        return 1;
    }

    /* Hide ~/.cache/bat/ — same reason */
    if (strncmp(rest, ".cache/bat", 10) == 0 &&
        (rest[10] == '\0' || rest[10] == '/')) {
        return 1;
    }

    return 0;
}
