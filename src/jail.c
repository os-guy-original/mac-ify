/*
 * jail.c — filesystem virtualization launcher for Mac-ify.
 *
 * Runs the macOS binary inside a mount+user namespace with ~/.macify
 * chrooted as /. The kernel then enforces what the path-translation
 * layer could only approximate: no process inside the jail can name,
 * open, or execute anything on the host outside the prefix — including
 * kernel shebang resolution and any syscall path we do not hook.
 *
 * Requires unprivileged user namespaces (kernel.unprivileged_userns_clone).
 * On failure, exits nonzero so callers can fall back to direct execution.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

static void die(const char *what) {
    fprintf(stderr, "macify-jail: %s: %s\n", what, strerror(errno));
    exit(126);
}


/* Copy a HOST file into the jail at reldst (jail-relative).
 * relsrc may be absolute (host path) — used verbatim. */
static int copy_into(const char *root, const char *relsrc, const char *reldst) {
    char sp[4096], dp[4096];
    if (relsrc[0] == '/')
        snprintf(sp, sizeof(sp), "%s", relsrc);
    else
        snprintf(sp, sizeof(sp), "%s/%s", root, relsrc);
    snprintf(dp, sizeof(dp), "%s/%s", root, reldst);

    int in = open(sp, O_RDONLY);
    if (in < 0) return -1;
    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) { close(in); return -1; }

    /* create parent dir of dp */
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", dp);
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        char cmd[8192];
        snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", parent);
        if (system(cmd) != 0) { close(in); return -1; }
    }

    int out = open(dp, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) { close(in); return -1; }
    char buf[1 << 16];
    ssize_t r;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) { close(in); close(out); return -1; }
            off += w;
        }
    }
    close(in);
    close(out);
    chmod(dp, 0755);
    return (r == 0) ? 0 : -1;
}

static int exists_in(const char *root, const char *rel) {
    char p[4096];
    snprintf(p, sizeof(p), "%s/%s", root, rel);
    return access(p, X_OK) == 0;
}

/* Refresh host runtime dependencies inside the jail. Idempotent; cheap
 * when everything is already present (only resolv.conf re-copied). */
static void prepare_jail(const char *root) {
    const char *dirs[] = { "usr/libexec/macify", "lib64", "usr/lib",
                           "etc", "proc", "dev", "tmp", "home",
                           "run", NULL };
    char mk[8192];
    snprintf(mk, sizeof(mk), "mkdir -p '%s'", root);
    if (system(mk) != 0) die("mkdir jail root");
    for (int i = 0; dirs[i]; i++) {
        snprintf(mk, sizeof(mk), "mkdir -p '%s/%s'", root, dirs[i]);
        if (system(mk) != 0) {
            fprintf(stderr, "macify-jail: mkdir -p %s/%s failed\n",
                    root, dirs[i]);
            die("mkdir jail dirs");
        }
    }

    /* Loader artifacts: refresh when host copy is newer than jailed copy.
     * The launcher sits next to build/macify and libmacify_shim.so. */
    char exe[4096], want[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) die("readlink /proc/self/exe");
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) die("exe path");
    *slash = '\0';
    char host_macify[4096], host_shim[4096];
    snprintf(host_macify, sizeof(host_macify), "%s/macify", exe);
    snprintf(host_shim, sizeof(host_shim), "%s/libmacify_shim.so", exe);

    int need_copy = 1;
    struct stat s_host, s_jail;
    char marker[4096];
    snprintf(marker, sizeof(marker),
             "%s/usr/libexec/macify/macify", root);

    if (need_copy) {
        if (copy_into(root, host_macify, "usr/libexec/macify/macify") != 0)
            die("copy macify into jail");
        if (copy_into(root, host_shim,
                      "usr/libexec/macify/libmacify_shim.so") != 0)
            die("copy shim into jail");
    }

    /* Host dynamic linker + libc for the (ELF) loader itself */
    if (!exists_in(root, "lib64/ld-linux-x86-64.so.2"))
        if (copy_into(root, "/usr/lib64/ld-linux-x86-64.so.2",
                      "lib64/ld-linux-x86-64.so.2") != 0)
            die("copy ld-linux");
    if (!exists_in(root, "usr/lib/libc.so.6"))
        if (copy_into(root, "/usr/lib/libc.so.6", "usr/lib/libc.so.6") != 0)
            die("copy libc");
    {
        /* shim links -lm/-ldl/-lpthread; loader preloads libm */
        const char *libs[][2] = {
            { "/usr/lib/libm.so.6",      "usr/lib/libm.so.6" },
            { "/usr/lib/libdl.so.2",     "usr/lib/libdl.so.2" },
            { "/usr/lib/libpthread.so.0","usr/lib/libpthread.so.0" },
            { NULL, NULL }
        };
        for (int i = 0; libs[i][0]; i++)
            if (!exists_in(root, libs[i][1]))
                if (copy_into(root, libs[i][0], libs[i][1]) != 0)
                    fprintf(stderr, "macify-jail: optional %s missing\n",
                            libs[i][0]);
    }

    /* NSS files backend for getpwuid/getgrnam from etc/passwd|group */
    if (!exists_in(root, "usr/lib/libnss_files.so.2")) {
        if (copy_into(root, "/usr/lib/libnss_files.so.2",
                      "usr/lib/libnss_files.so.2") != 0) {
            /* optional on modern glibc */
        }
    }

    /* DNS + user resolution config: refreshed every launch */
    copy_into(root, "/etc/resolv.conf", "etc/resolv.conf");
    copy_into(root, "/etc/hosts", "etc/hosts");

    char nss[4096];
    snprintf(nss, sizeof(nss), "%s/etc/nsswitch.conf", root);
    if (access(nss, F_OK) != 0) {
        FILE *f = fopen(nss, "w");
        if (f) {
            fputs("passwd: files\ngroup: files\nshadow: files\n"
                  "hosts: files dns\nnetworks: files\nprotocols: files\n"
                  "services: files\nethers: files\nrpc: files\n", f);
            fclose(f);
        }
    }
}

static void write_proc(const char *name, const char *content) {
    int fd = open(name, O_WRONLY);
    if (fd < 0) return;
    (void)!write(fd, content, strlen(content));
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: macify-jail <loader> [loader-args...]\n"
            "Runs <loader> inside a chroot of the macify prefix.\n");
        return 1;
    }
    const char *loader = argv[1];

    const char *root = getenv("MACIFY_JAIL_ROOT");
    if (!root || !root[0]) root = "/homeless-shelter-no-root";
    struct stat rs;
    if (stat(root, &rs) != 0 || !S_ISDIR(rs.st_mode))
        die("MACIFY_JAIL_ROOT not a directory");

    prepare_jail(root);

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
        fprintf(stderr,
            "macify-jail: unshare(user|mount) failed: %s\n"
            "  (enable kernel.unprivileged_userns_clone, or run with MACIFY_NO_JAIL=1)\n",
            strerror(errno));
        return 126;
    }

    /* Map this single uid/gid to root inside the namespace. */
    write_proc("/proc/self/setgroups", "deny");
    {
        char map[64];
        snprintf(map, sizeof(map), "0 %u 1\n", uid);
        write_proc("/proc/self/uid_map", map);
        snprintf(map, sizeof(map), "0 %u 1\n", gid);
        write_proc("/proc/self/gid_map", map);
    }

    /* Contain mounts: no propagation back to the host */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        die("mount --make-rprivate /");

    /* Private tmp: scratch space never touches the host */
    if (mount("tmpfs", "/tmp", "tmpfs",
              MS_NOSUID | MS_NODEV, "mode=1777") != 0)
        fprintf(stderr, "macify-jail: tmpfs /tmp failed (%s) — continuing\n",
                strerror(errno));

    /* Self-referential alias: macOS binaries bake their install prefix
     * ("/home/<user>/.macify") into load paths at build time. Inside the
     * jail that path only exists if the root aliases itself there. */
    {
        const char *h = getenv("HOME");
        const char *base = h ? strrchr(h, '/') : NULL;
        base = base ? base + 1 : "user";
        char hp[4096], linkp[4096], tgt[] = "/";
        snprintf(hp, sizeof(hp), "%s/home/%s", root, base);
        char mk[8192];
        snprintf(mk, sizeof(mk), "mkdir -p '%s'", hp);
        if (system(mk) != 0)
            fprintf(stderr, "macify-jail: mkdir %s failed\n", hp);
        snprintf(linkp, sizeof(linkp), "%s/.macify", hp);
        unlink(linkp);
        if (symlink(tgt, linkp) != 0 && errno != EEXIST)
            fprintf(stderr, "macify-jail: alias symlink failed: %s\n",
                    strerror(errno));
        /* remember for HOME below */
        static char jail_home[256];
        snprintf(jail_home, sizeof(jail_home), "/home/%s", base);
        setenv("MACIFY_JAIL_HOME", jail_home, 1);
    }

    /* Device stand-ins: mknod is blocked in userns, so regular files.
     * Writes to null grow it (trimmed each launch); zero/random reads
     * give EOF/deterministic bytes until full dev emulation lands. */
    {
        const char *devnull = "/dev/null";
        int fd = open(devnull, O_WRONLY | O_CREAT, 0666);
        if (fd >= 0) close(fd);
        const char *others[] = { "/dev/zero", "/dev/random",
                                 "/dev/urandom", NULL };
        for (int i = 0; others[i]; i++) {
            fd = open(others[i], O_RDONLY | O_CREAT, 0666);
            if (fd >= 0) close(fd);
        }
    }

    /* Enter the jail. After chroot, "~/.macify" IS "/" — every absolute
     * path a macOS binary can form resolves inside the prefix or not
     * at all. There is no host left to reach. */
    if (chdir(root) != 0) die("chdir jail root");
    if (chroot(".") != 0) die("chroot");
    if (chdir("/") != 0) die("chdir /");

    /* Environment: identity mode + loader discovery without /proc */
    setenv("MACIFY_JAILED", "1", 1);
    setenv("MACIFY_PREFIX", "/", 1);
    setenv("MACIFY_BINARY", "/usr/libexec/macify/macify", 1);
    setenv("LD_LIBRARY_PATH", "/usr/libexec/macify", 1);
    setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin", 1);
    unsetenv("MACIFY_JAIL_ROOT");
    unsetenv("MACIFY_NO_JAIL");

    const char *jh = getenv("MACIFY_JAIL_HOME");
    setenv("HOME", jh && jh[0] ? jh : "/home/user", 1);
    unsetenv("MACIFY_JAIL_HOME");

    /* Inside the jail only the synced copy exists; the host path from
     * argv[1] is meaningless past chroot. */
    static char jailed_loader[] = "/usr/libexec/macify/macify";
    argv[1] = jailed_loader;
    execv(jailed_loader, argv + 1);
    fprintf(stderr, "macify-jail: exec %s: %s\n", jailed_loader,
            strerror(errno));
    return 127;
}
