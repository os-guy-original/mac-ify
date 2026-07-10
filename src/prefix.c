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

    snprintf(path, sizeof(path), "%s/usr/bin", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/sbin", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local/lib", prefix);
    ensure_dir(path);

    snprintf(path, sizeof(path), "%s/usr/local/bin", prefix);
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
 * This implements a Wine-style fake rootfs: the macify prefix (~/.macify/)
 * IS the root filesystem for macOS binaries. Every absolute path /foo
 * becomes <prefix>/foo, so macOS binaries see their own macOS binaries
 * in /bin/, /usr/bin/, etc. — never Linux binaries.
 *
 * Translation rules:
 *   /foo/bar          → <prefix>/foo/bar    (Wine-style rootfs)
 *   ~/Library/...     → <prefix>/Library/...
 *   ~/... (non-Lib)   → pass through (home dir access)
 *   /dev/...          → pass through (real devices)
 *   /proc/...         → pass through (Linux procfs)
 *   /sys/...          → pass through (Linux sysfs)
 *   /tmp/...          → pass through (shared temp dir)
 *   relative paths    → pass through
 */
int macify_translate_path(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) return -1;

    const char *prefix = macify_get_prefix();
    if (!prefix || macify_prefix_len == 0) return -1;

    /* Only translate absolute paths */
    if (path[0] != '/') {
        /* Handle ~/Library/ specially */
        const char *home = getenv("HOME");
        size_t home_len = home ? strlen(home) : 0;
        if (home && strncmp(path, home, home_len) == 0 && path[home_len] == '/') {
            if (strncmp(path + home_len + 1, "Library/", 8) == 0 ||
                strcmp(path + home_len + 1, "Library") == 0) {
                snprintf(out, out_size, "%s%s", prefix, path + home_len);
                return 0;
            }
        }
        /* Relative paths pass through */
        return -1;
    }

    /* ── Exceptions: paths that pass through to the real filesystem ── */

    /* /dev/ — real device files (ttys, null, zero, etc.) */
    if (strncmp(path, "/dev/", 5) == 0 || strcmp(path, "/dev") == 0)
        return -1;

    /* /proc/ — Linux procfs (some macOS binaries read /proc/self) */
    if (strncmp(path, "/proc/", 6) == 0 || strcmp(path, "/proc") == 0)
        return -1;

    /* /sys/ — Linux sysfs */
    if (strncmp(path, "/sys/", 5) == 0 || strcmp(path, "/sys") == 0)
        return -1;

    /* /tmp/ — shared temp directory */
    if (strncmp(path, "/tmp/", 5) == 0 || strcmp(path, "/tmp") == 0)
        return -1;

    /* ── All other absolute paths: translate to prefix ── */
    /* /bin/sh          → <prefix>/bin/sh
     * /usr/bin/ls      → <prefix>/usr/bin/ls
     * /usr/local/brew  → <prefix>/usr/local/brew
     * /etc/passwd      → <prefix>/etc/passwd
     * /Library/...     → <prefix>/Library/... */
    snprintf(out, out_size, "%s%s", prefix, path);
    return 0;
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

    /* Hide Linux XDG directories — macOS binaries must use ~/Library/ instead.
     * If a macOS binary reads ~/.config/foo, it gets Linux-format config that
     * can crash or produce wrong results. By hiding these, the binary falls
     * back to macOS-style paths (~/Library/Preferences/, ~/Library/Caches/,
     * ~/Library/Application Support/) which are translated to the prefix.
     *
     * Hidden:
     *   ~/.config/       — Linux XDG config (macOS: ~/Library/Preferences/)
     *   ~/.cache/        — Linux XDG cache (macOS: ~/Library/Caches/)
     *   ~/.local/        — Linux XDG data (macOS: ~/Library/Application Support/)
     *   ~/.local/share/  — Linux XDG shared data
     *   ~/.local/state/  — Linux XDG state data
     *   ~/.pki/          — Linux certificate store (macOS: keychain)
     *   ~/.gnupg/        — Linux GPG (macOS: different layout)
     *
     * NOT hidden (needed by both platforms):
     *   ~/.ssh/          — SSH config is compatible across platforms
     *   ~/.macify/       — our own prefix
     */
    static const char *hidden_dirs[] = {
        ".config",
        ".cache",
        ".local",
        ".pki",
        ".gnupg",
        NULL
    };

    for (int i = 0; hidden_dirs[i]; i++) {
        const char *dir = hidden_dirs[i];
        size_t dlen = strlen(dir);
        if (strncmp(rest, dir, dlen) == 0 &&
            (rest[dlen] == '\0' || rest[dlen] == '/')) {
            if (getenv("MACIFY_TRACE_OPEN")) {
                char b[512]; int n = snprintf(b, sizeof(b),
                    "macify: HIDE \"%s\" (returning ENOENT)\n", path);
                (void)write(2, b, n);
            }
            return 1;
        }
    }

    return 0;
}
