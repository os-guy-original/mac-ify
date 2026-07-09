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

/* Get the prefix path (~/.macify or $MACIFY_PREFIX) */
const char *macify_get_prefix(void) {
    if (macify_prefix_initialized) return macify_prefix;

    /* Allow custom prefix via environment variable (like WINEPREFIX) */
    const char *env_prefix = getenv("MACIFY_PREFIX");
    if (env_prefix && env_prefix[0]) {
        snprintf(macify_prefix, sizeof(macify_prefix), "%s", env_prefix);
    } else {
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
        snprintf(macify_prefix, sizeof(macify_prefix), "%s/.macify", home);
    }
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
 * Called from main() before the macOS binary's main().
 *
 * This creates a Wine-like prefix at ~/.macify/ with a full macOS
 * filesystem structure. macOS binaries see these paths and think
 * they're running on a real Apple machine.
 *
 * Structure created:
 *   ~/.macify/
 *   ├── .macify_prefix          (marker file)
 *   ├── Library/
 *   │   ├── Caches/
 *   │   ├── Preferences/
 *   │   ├── Application Support/
 *   │   ├── Logs/
 *   │   ├── LaunchAgents/       (empty, for launchd compatibility)
 *   │   └── Frameworks/         (empty, for framework loading)
 *   ├── System/
 *   │   └── Library/
 *   │       ├── CoreServices/
 *   │       │   └── SystemVersion.plist  (macOS version info)
 *   │       └── Frameworks/
 *   ├── usr/
 *   │   ├── lib/                (macOS-style lib, for dylib loading)
 *   │   └── local/lib/
 *   ├── etc/
 *   │   ├── passwd              (macOS-style passwd for getpwuid)
 *   │   ├── group               (macOS-style group for getgrgid)
 *   │   └── localtime           (timezone, symlink to /usr/share/zoneinfo)
 *   ├── var/
 *   │   └── log/                (macOS-style /var/log)
 *   ├── tmp/                    (symlink to /tmp)
 *   └── bin/                    (empty, for PATH compatibility) */
void macify_init_prefix(void) {
    const char *prefix = macify_get_prefix();
    if (!prefix || macify_prefix_len == 0) return;

    char path[PATH_MAX];
    char path2[PATH_MAX];

    /* Create prefix root */
    ensure_dir(prefix);

    /* ── Library/ ────────────────────────────────────────── */
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

    snprintf(path, sizeof(path), "%s/Library/LaunchAgents", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/Library/Frameworks", prefix);
    ensure_dir(path);

    /* ── System/Library/ ────────────────────────────────── */
    snprintf(path, sizeof(path), "%s/System", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/System/Library", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/System/Library/CoreServices", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/System/Library/Frameworks", prefix);
    ensure_dir(path);

    /* Write SystemVersion.plist — macOS binaries read this to determine
     * the OS version. We report macOS 14.5 (Sonoma) for compatibility. */
    snprintf(path, sizeof(path), "%s/System/Library/CoreServices/SystemVersion.plist", prefix);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>ProductBuildVersion</key>\n"
            "    <string>23F79</string>\n"
            "    <key>ProductCopyright</key>\n"
            "    <string>1983-2024 Apple Inc.</string>\n"
            "    <key>ProductName</key>\n"
            "    <string>macOS</string>\n"
            "    <key>ProductUserVisibleVersion</key>\n"
            "    <string>14.5</string>\n"
            "    <key>ProductVersion</key>\n"
            "    <string>14.5</string>\n"
            "    <key>iOSSupportVersion</key>\n"
            "    <string>17.5</string>\n"
            "</dict>\n"
            "</plist>\n");
        fclose(f);
    }

    /* Write ServerVersion.plist (some tools check this) */
    snprintf(path, sizeof(path), "%s/System/Library/CoreServices/ServerVersion.plist", prefix);
    f = fopen(path, "w");
    if (f) {
        fprintf(f,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>ProductBuildVersion</key>\n"
            "    <string>23F79</string>\n"
            "    <key>ProductCopyright</key>\n"
            "    <string>1983-2024 Apple Inc.</string>\n"
            "    <key>ProductName</key>\n"
            "    <string>macOS Server</string>\n"
            "    <key>ProductUserVisibleVersion</key>\n"
            "    <string>14.5</string>\n"
            "    <key>ProductVersion</key>\n"
            "    <string>14.5</string>\n"
            "</dict>\n"
            "</plist>\n");
        fclose(f);
    }

    /* ── usr/ ────────────────────────────────────────────── */
    snprintf(path, sizeof(path), "%s/usr", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/lib", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local/lib", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/share", prefix);
    ensure_dir(path);

    /* ── etc/ — macOS-specific config files ─────────────── */
    snprintf(path, sizeof(path), "%s/etc", prefix);
    ensure_dir(path);

    /* Write /etc/passwd — macOS-style passwd for getpwuid.
     * macOS passwd format: name:passwd:uid:gid:gecos:home:shell */
    snprintf(path, sizeof(path), "%s/etc/passwd", prefix);
    f = fopen(path, "w");
    if (f) {
        const char *user = getenv("USER");
        if (!user) user = "user";
        const char *home = getenv("HOME");
        if (!home) home = "/home/user";
        uid_t uid = getuid();
        gid_t gid = getgid();
        fprintf(f, "##\n# User Database\n##\n");
        fprintf(f, "nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n");
        fprintf(f, "root:*:0:0:System Administrator:/var/root:/bin/sh\n");
        fprintf(f, "daemon:*:1:1:System Services:/var/root:/usr/bin/false\n");
        fprintf(f, "%s:*:%d:%d:User:%s:/bin/bash\n", user, uid, gid, home);
        fclose(f);
    }

    /* Write /etc/group — macOS-style group for getgrgid */
    snprintf(path, sizeof(path), "%s/etc/group", prefix);
    f = fopen(path, "w");
    if (f) {
        gid_t gid = getgid();
        const char *user = getenv("USER");
        if (!user) user = "user";
        fprintf(f, "##\n# Group Database\n##\n");
        fprintf(f, "nobody:*:-2:\n");
        fprintf(f, "wheel:*:0:root\n");
        fprintf(f, "daemon:*:1:\n");
        fprintf(f, "staff:*:20:\n");
        fprintf(f, "%s:*:%d:%s\n", user, gid, user);
        fclose(f);
    }

    /* Write /etc/shells — macOS-style shells list */
    snprintf(path, sizeof(path), "%s/etc/shells", prefix);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "/bin/bash\n/bin/sh\n/bin/zsh\n/usr/bin/bash\n/usr/bin/sh\n/usr/bin/zsh\n");
        fclose(f);
    }

    /* ── var/ ────────────────────────────────────────────── */
    snprintf(path, sizeof(path), "%s/var", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/var/log", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/var/root", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/var/empty", prefix);
    ensure_dir(path);

    /* ── tmp/ — symlink to /tmp ─────────────────────────── */
    snprintf(path, sizeof(path), "%s/tmp", prefix);
    snprintf(path2, sizeof(path2), "/tmp");
    struct stat st;
    if (lstat(path, &st) != 0) {
        symlink(path2, path);
    }

    /* ── bin/ — empty for PATH compatibility ─────────────── */
    snprintf(path, sizeof(path), "%s/bin", prefix);
    ensure_dir(path);

    /* ── dev/ — symlink to /dev ──────────────────────────── */
    snprintf(path, sizeof(path), "%s/dev", prefix);
    if (lstat(path, &st) != 0) {
        symlink("/dev", path);
    }

    /* Create ~/Library symlink → ~/.macify/Library
     * This makes ~/Library/Caches/bat work for macOS binaries.
     * Only create if ~/Library doesn't already exist. */
    const char *home = getenv("HOME");
    if (home) {
        char home_library[PATH_MAX];
        snprintf(home_library, sizeof(home_library), "%s/Library", home);

        char prefix_library[PATH_MAX];
        snprintf(prefix_library, sizeof(prefix_library), "%s/Library", prefix);

        if (lstat(home_library, &st) != 0) {
            symlink(prefix_library, home_library);
        }
    }

    /* Write a marker file so we know the prefix is initialized */
    snprintf(path, sizeof(path), "%s/.macify_prefix", prefix);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "macify prefix v2\n");
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
 *   /etc/passwd          → ~/.macify/etc/passwd (macOS-style passwd)
 *   /etc/group           → ~/.macify/etc/group
 *   /etc/shells          → ~/.macify/etc/shells
 *   /var/log/...         → ~/.macify/var/log/...
 *   /var/root/...        → ~/.macify/var/root/...
 *   /usr/lib/...         → pass through (dylib loading handled by shim)
 *   /usr/local/...       → pass through
 *   /tmp/                → pass through (symlinked in prefix)
 *   /etc/ (other)        → pass through (use real /etc for system config)
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

    /* /etc/passwd, /etc/group, /etc/shells → prefix etc/
     * (macOS-style passwd/group differ from Linux) */
    if (strcmp(path, "/etc/passwd") == 0 ||
        strcmp(path, "/etc/group") == 0 ||
        strcmp(path, "/etc/shells") == 0) {
        snprintf(out, out_size, "%s%s", prefix, path);
        return 0;
    }

    /* /var/log/... → prefix var/log/ */
    if (strncmp(path, "/var/log/", 9) == 0 || strcmp(path, "/var/log") == 0) {
        snprintf(out, out_size, "%s%s", prefix, path);
        return 0;
    }

    /* /var/root/... → prefix var/root/ */
    if (strncmp(path, "/var/root/", 10) == 0 || strcmp(path, "/var/root") == 0) {
        snprintf(out, out_size, "%s%s", prefix, path);
        return 0;
    }

    /* /var/empty → prefix var/empty */
    if (strcmp(path, "/var/empty") == 0) {
        snprintf(out, out_size, "%s%s", prefix, path);
        return 0;
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
        if (getenv("MACIFY_TRACE_OPEN")) {
            char b[512]; int n = snprintf(b, sizeof(b),
                "macify: HIDE \"%s\" (returning ENOENT)\n", path);
            (void)write(2, b, n);
        }
        return 1;
    }

    /* Hide ~/.cache/bat/ — same reason */
    if (strncmp(rest, ".cache/bat", 10) == 0 &&
        (rest[10] == '\0' || rest[10] == '/')) {
        if (getenv("MACIFY_TRACE_OPEN")) {
            char b[512]; int n = snprintf(b, sizeof(b),
                "macify: HIDE \"%s\" (returning ENOENT)\n", path);
            (void)write(2, b, n);
        }
        return 1;
    }

    return 0;
}
