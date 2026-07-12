#include "shim.h"
#include <spawn.h>

/* macOS posix_spawnattr_t: ~16-32 bytes (opaque, small)
 * Linux posix_spawnattr_t: 336 bytes
 * macOS posix_spawn_file_actions_t: ~16 bytes (pointer-based)
 * Linux posix_spawn_file_actions_t: 80 bytes
 *
 * If we let macOS binaries call Linux's posix_spawnattr_init directly,
 * it writes 336 bytes into a macOS-sized buffer, corrupting the stack.
 *
 * Solution: provide macOS-sized structs and translate to Linux's format
 * when posix_spawn/posix_spawnp is actually called. */

/* macOS spawn flags */
#define MACOS_POSIX_SPAWN_SETPGROUP    0x0001
#define MACOS_POSIX_SPAWN_SETSIGDEF    0x0004

/* Our internal posix_spawnattr_t — fits in macOS's buffer (~32 bytes) */
typedef struct {
    uint32_t flags;
    int32_t  pgid;
    uint32_t sigdefault_lo;
    uint32_t has_sigdefault;
    uint32_t __pad[3];
} macify_spawnattr_t;

/* Our internal file_actions — linked list, pointer stored in macOS buffer */
typedef struct macify_spawn_action {
    int type;       /* 0=addclose, 1=adddup2, 2=addopen */
    int fd;
    int newfd;
    int oflag;
    mode_t mode;
    char *path;
    struct macify_spawn_action *next;
} macify_spawn_action_t;

typedef struct {
    macify_spawn_action_t *head;
    macify_spawn_action_t *tail;
    int count;
    char __pad[4];
} macify_file_actions_t;

int macify_posix_spawnattr_init(void *attr) __asm__("posix_spawnattr_init");
int macify_posix_spawnattr_init(void *attr) {
    if (!attr) return EINVAL;
    memset(attr, 0, sizeof(macify_spawnattr_t));
    return 0;
}

int macify_posix_spawnattr_destroy(void *attr) __asm__("posix_spawnattr_destroy");
int macify_posix_spawnattr_destroy(void *attr) {
    if (!attr) return EINVAL;
    memset(attr, 0, sizeof(macify_spawnattr_t));
    return 0;
}

int macify_posix_spawnattr_setflags(void *attr, short flags) __asm__("posix_spawnattr_setflags");
int macify_posix_spawnattr_setflags(void *attr, short flags) {
    if (!attr) return EINVAL;
    ((macify_spawnattr_t *)attr)->flags = (uint32_t)flags;
    return 0;
}

int macify_posix_spawnattr_setpgroup(void *attr, pid_t pgid) __asm__("posix_spawnattr_setpgroup");
int macify_posix_spawnattr_setpgroup(void *attr, pid_t pgid) {
    if (!attr) return EINVAL;
    macify_spawnattr_t *a = (macify_spawnattr_t *)attr;
    a->flags |= MACOS_POSIX_SPAWN_SETPGROUP;
    a->pgid = pgid;
    return 0;
}

int macify_posix_spawnattr_setsigdefault(void *attr, const void *sigdefault) __asm__("posix_spawnattr_setsigdefault");
int macify_posix_spawnattr_setsigdefault(void *attr, const void *sigdefault) {
    if (!attr || !sigdefault) return EINVAL;
    macify_spawnattr_t *a = (macify_spawnattr_t *)attr;
    memcpy(&a->sigdefault_lo, sigdefault, sizeof(uint32_t));
    a->has_sigdefault = 1;
    a->flags |= MACOS_POSIX_SPAWN_SETSIGDEF;
    return 0;
}

/* posix_spawnattr_setbinpref — macOS-specific, sets the binary preference
 * (architecture). Not applicable on Linux; accept and ignore. */
int macify_posix_spawnattr_setbinpref(void *attr, size_t count, const void *pref, size_t *ocount) __asm__("posix_spawnattr_setbinpref");
int macify_posix_spawnattr_setbinpref(void *attr, size_t count, const void *pref, size_t *ocount) {
    (void)attr; (void)pref;
    /* macOS API: returns 0 on success and sets *ocount to the number of
     * cpu types actually copied. Python checks that *ocount == count. */
    if (ocount) *ocount = count;
    if (getenv("MACIFY_TRACE_SPAWN")) fprintf(stderr, "macify: posix_spawnattr_setbinpref called (count=%zu, stub returns 0)\n", count);
    return 0;
}

/* posix_spawnattr_setbinpref_np — same as setbinpref but with _np suffix.
 * Some macOS binaries reference this variant. */
int macify_posix_spawnattr_setbinpref_np(void *attr, size_t count, const void *pref, size_t *ocount) __asm__("posix_spawnattr_setbinpref_np");
int macify_posix_spawnattr_setbinpref_np(void *attr, size_t count, const void *pref, size_t *ocount) {
    return macify_posix_spawnattr_setbinpref(attr, count, pref, ocount);
}

/* posix_spawnattr_setprocinfo_mask / setcpumonitor — macOS-specific,
 * not applicable on Linux. */
int macify_posix_spawnattr_setprocinfo_mask(void *attr, uint32_t mask) __asm__("posix_spawnattr_setprocinfo_mask");
int macify_posix_spawnattr_setprocinfo_mask(void *attr, uint32_t mask) {
    (void)attr; (void)mask; return 0;
}

int macify_posix_spawnattr_setcpumonitor(void *attr, uint32_t quota, uint32_t interval) __asm__("posix_spawnattr_setcpumonitor");
int macify_posix_spawnattr_setcpumonitor(void *attr, uint32_t quota, uint32_t interval) {
    (void)attr; (void)quota; (void)interval; return 0;
}

int macify_posix_spawn_file_actions_init(void *fa) __asm__("posix_spawn_file_actions_init");
int macify_posix_spawn_file_actions_init(void *fa) {
    if (!fa) return EINVAL;
    macify_file_actions_t *mfa = calloc(1, sizeof(macify_file_actions_t));
    if (!mfa) return ENOMEM;
    *(void **)fa = mfa;
    return 0;
}

int macify_posix_spawn_file_actions_destroy(void *fa) __asm__("posix_spawn_file_actions_destroy");
int macify_posix_spawn_file_actions_destroy(void *fa) {
    if (!fa) return EINVAL;
    macify_file_actions_t *mfa = *(macify_file_actions_t **)fa;
    if (!mfa) return 0;
    macify_spawn_action_t *act = mfa->head;
    while (act) {
        macify_spawn_action_t *next = act->next;
        if (act->path) free(act->path);
        free(act);
        act = next;
    }
    free(mfa);
    *(void **)fa = NULL;
    return 0;
}

int macify_posix_spawn_file_actions_adddup2(void *fa, int fd, int newfd) __asm__("posix_spawn_file_actions_adddup2");
int macify_posix_spawn_file_actions_adddup2(void *fa, int fd, int newfd) {
    if (!fa) return EINVAL;
    macify_file_actions_t *mfa = *(macify_file_actions_t **)fa;
    if (!mfa) return EINVAL;
    macify_spawn_action_t *act = calloc(1, sizeof(macify_spawn_action_t));
    if (!act) return ENOMEM;
    act->type = 1;
    act->fd = fd;
    act->newfd = newfd;
    if (mfa->tail) mfa->tail->next = act;
    else mfa->head = act;
    mfa->tail = act;
    mfa->count++;
    return 0;
}

int macify_posix_spawn_file_actions_addclose(void *fa, int fd) __asm__("posix_spawn_file_actions_addclose");
int macify_posix_spawn_file_actions_addclose(void *fa, int fd) {
    if (!fa) return EINVAL;
    macify_file_actions_t *mfa = *(macify_file_actions_t **)fa;
    if (!mfa) return EINVAL;
    macify_spawn_action_t *act = calloc(1, sizeof(macify_spawn_action_t));
    if (!act) return ENOMEM;
    act->type = 0;
    act->fd = fd;
    if (mfa->tail) mfa->tail->next = act;
    else mfa->head = act;
    mfa->tail = act;
    mfa->count++;
    return 0;
}

int macify_posix_spawn_file_actions_addopen(void *fa, int fd, const char *path, int oflag, mode_t mode) __asm__("posix_spawn_file_actions_addopen");
int macify_posix_spawn_file_actions_addopen(void *fa, int fd, const char *path, int oflag, mode_t mode) {
    if (!fa || !path) return EINVAL;
    macify_file_actions_t *mfa = *(macify_file_actions_t **)fa;
    if (!mfa) return EINVAL;
    macify_spawn_action_t *act = calloc(1, sizeof(macify_spawn_action_t));
    if (!act) return ENOMEM;
    act->type = 2;
    act->fd = fd;
    act->oflag = oflag;
    act->mode = mode;
    act->path = strdup(path);
    if (!act->path) { free(act); return ENOMEM; }
    if (mfa->tail) mfa->tail->next = act;
    else mfa->head = act;
    mfa->tail = act;
    mfa->count++;
    return 0;
}

/* posix_spawn_file_actions_addinherit_np — macOS-specific function
 * to mark an fd as inheritable by the spawned process.
 * On Linux, fds are inheritable by default (unless O_CLOEXEC is set).
 * This is a no-op on Linux. */
int macify_posix_spawn_file_actions_addinherit_np(void *fa, int fd) __asm__("posix_spawn_file_actions_addinherit_np");
int macify_posix_spawn_file_actions_addinherit_np(void *fa, int fd) {
    (void)fa; (void)fd;
    return 0;  /* no-op — Linux fds are inheritable by default */
}

/* posix_spawn_file_actions_addchdir_np — macOS-specific chdir action */
int macify_posix_spawn_file_actions_addchdir_np(void *fa, const char *path) __asm__("posix_spawn_file_actions_addchdir_np");
int macify_posix_spawn_file_actions_addchdir_np(void *fa, const char *path) {
    if (!fa || !path) return EINVAL;
    macify_file_actions_t *mfa = *(macify_file_actions_t **)fa;
    if (!mfa) return EINVAL;
    macify_spawn_action_t *act = calloc(1, sizeof(macify_spawn_action_t));
    if (!act) return ENOMEM;
    act->type = 3;  /* chdir */
    act->path = strdup(path);
    if (!act->path) { free(act); return ENOMEM; }
    if (mfa->tail) mfa->tail->next = act;
    else mfa->head = act;
    mfa->tail = act;
    mfa->count++;
    return 0;
}

/* posix_spawn_file_actions_addfchdir_np — macOS-specific fchdir action */
int macify_posix_spawn_file_actions_addfchdir_np(void *fa, int fd) __asm__("posix_spawn_file_actions_addfchdir_np");
int macify_posix_spawn_file_actions_addfchdir_np(void *fa, int fd) {
    if (!fa) return EINVAL;
    macify_file_actions_t *mfa = *(macify_file_actions_t **)fa;
    if (!mfa) return EINVAL;
    macify_spawn_action_t *act = calloc(1, sizeof(macify_spawn_action_t));
    if (!act) return ENOMEM;
    act->type = 4;  /* fchdir */
    act->fd = fd;
    if (mfa->tail) mfa->tail->next = act;
    else mfa->head = act;
    mfa->tail = act;
    mfa->count++;
    return 0;
}

/* Forward declarations for functions defined later in this file */
static int is_macho_binary(const char *path);
static const char *get_macify_binary(void);
static char **build_macify_argv(const char *target, char *const argv[]);
static int resolve_in_prefix_path(const char *file, char *out, size_t out_size);

static int do_posix_spawn(pid_t *pid, const char *path,
                          const void *file_actions, const void *attrp,
                          char *const argv[], char *const envp[],
                          int use_path) {
    /* If path is NULL, return 0 (success) with pid=0. Python probes
     * posix_spawn with NULL path during initialization. */
    if (!path) {
        if (pid) *pid = 0;
        return 0;
    }

    /* Resolve the path:
     * - For posix_spawn (use_path=0): translate the absolute path
     * - For posix_spawnp (use_path=1): search PATH in prefix
     */
    char resolved[4096];
    const char *eff_path = path;

    if (use_path) {
        /* posix_spawnp — search PATH */
        if (resolve_in_prefix_path(path, resolved, sizeof(resolved)) != 0) {
            /* Not found — fall through to real posix_spawnp which will
             * return ENOENT. Use original path. */
            eff_path = path;
        } else {
            eff_path = resolved;
        }
    } else {
        /* posix_spawn — translate absolute path */
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(path, resolved, sizeof(resolved)) == 0)
            eff_path = resolved;
    }

    if (getenv("MACIFY_TRACE_SPAWN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: posix_spawn%s(\"%s\" -> \"%s\")\n",
            use_path ? "p" : "", path, eff_path);
        (void)write(2, b, n);
    }

    /* If it's a Mach-O binary, fork + exec through macify */
    if (is_macho_binary(eff_path)) {
        const char *macify_bin = get_macify_binary();
        if (macify_bin) {
            char **new_argv = build_macify_argv(eff_path, argv);
            if (new_argv) {
                /* Use fork + execve since posix_spawn can't handle
                 * re-execing through macify with file_actions. */
                pid_t child = fork();
                if (child == 0) {
                    /* Child: exec macify with the new argv.
                     * Ensure LD_LIBRARY_PATH is set so macify can find the shim. */
                    if (!getenv("LD_LIBRARY_PATH")) {
                        char libpath[4096];
                        strncpy(libpath, macify_bin, sizeof(libpath) - 1);
                        libpath[sizeof(libpath) - 1] = '\0';
                        char *slash = strrchr(libpath, '/');
                        if (slash) *slash = '\0';
                        setenv("LD_LIBRARY_PATH", libpath, 1);
                    }
                    /* Ensure MACIFY_BINARY is set for nested execs */
                    setenv("MACIFY_BINARY", macify_bin, 1);
                    /* Ensure MACIFY_PREFIX is set */
                    if (!getenv("MACIFY_PREFIX")) {
                        extern const char *macify_get_prefix(void);
                        const char *pfx = macify_get_prefix();
                        if (pfx) setenv("MACIFY_PREFIX", pfx, 1);
                    }
                    static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
                    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");
                    if (real_execve) real_execve(macify_bin, new_argv, environ);
                    _exit(127);
                }
                free(new_argv);
                if (child < 0) return errno;
                if (pid) *pid = child;
                return 0;
            }
        }
    }

    /* ELF or unknown — use real posix_spawn with translated path */
    posix_spawnattr_t linux_attr;
    posix_spawn_file_actions_t linux_fa;

    memset(&linux_attr, 0, sizeof(linux_attr));
    posix_spawnattr_init(&linux_attr);
    if (attrp) {
        macify_spawnattr_t *macos_attr = (macify_spawnattr_t *)attrp;
        short flags = 0;
        if (macos_attr->flags & MACOS_POSIX_SPAWN_SETPGROUP) flags |= POSIX_SPAWN_SETPGROUP;
        if (macos_attr->flags & MACOS_POSIX_SPAWN_SETSIGDEF) flags |= POSIX_SPAWN_SETSIGDEF;
        if (flags) posix_spawnattr_setflags(&linux_attr, flags);
        if (macos_attr->flags & MACOS_POSIX_SPAWN_SETPGROUP)
            posix_spawnattr_setpgroup(&linux_attr, macos_attr->pgid);
    }

    memset(&linux_fa, 0, sizeof(linux_fa));
    posix_spawn_file_actions_init(&linux_fa);
    if (file_actions) {
        macify_file_actions_t *mfa = *(macify_file_actions_t **)file_actions;
        if (mfa) {
            macify_spawn_action_t *act = mfa->head;
            while (act) {
                switch (act->type) {
                    case 0: posix_spawn_file_actions_addclose(&linux_fa, act->fd); break;
                    case 1: posix_spawn_file_actions_adddup2(&linux_fa, act->fd, act->newfd); break;
                    case 2: posix_spawn_file_actions_addopen(&linux_fa, act->fd, act->path, act->oflag, act->mode); break;
                }
                act = act->next;
            }
        }
    }

    int ret;
    {
        static pid_t (*real_spawn)(pid_t *, const char *,
                                    const posix_spawn_file_actions_t *,
                                    const posix_spawnattr_t *,
                                    char *const [], char *const []) = NULL;
        static pid_t (*real_spawnp)(pid_t *, const char *,
                                     const posix_spawn_file_actions_t *,
                                     const posix_spawnattr_t *,
                                     char *const [], char *const []) = NULL;
        if (use_path) {
            if (!real_spawnp) real_spawnp = dlsym(RTLD_NEXT, "posix_spawnp");
            if (real_spawnp) ret = real_spawnp(pid, eff_path, &linux_fa, &linux_attr, argv, envp);
            else ret = ENOSYS;
        } else {
            if (!real_spawn) real_spawn = dlsym(RTLD_NEXT, "posix_spawn");
            if (real_spawn) ret = real_spawn(pid, eff_path, &linux_fa, &linux_attr, argv, envp);
            else ret = ENOSYS;
        }
    }

    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: posix_spawn%s(\"%s\") = %d%s\n",
            use_path ? "p" : "",
            path ? path : "(null)",
            ret,
            (argv && argv[0]) ? "" : "");
        (void)write(2, b, n);
        if (argv) {
            int i;
            for (i = 0; argv[i] && i < 8; i++) {
                n = snprintf(b, sizeof(b), "  argv[%d] = \"%s\"\n", i, argv[i]);
                (void)write(2, b, n);
            }
        }
    }

    /* Call glibc's real destroy functions, NOT our overrides.
     * Our overrides expect macOS-format buffers; these are glibc structs. */
    {
        static int (*real_fa_destroy)(void *) = NULL;
        static int (*real_attr_destroy)(void *) = NULL;
        if (!real_fa_destroy) real_fa_destroy = dlsym(RTLD_NEXT, "posix_spawn_file_actions_destroy");
        if (!real_attr_destroy) real_attr_destroy = dlsym(RTLD_NEXT, "posix_spawnattr_destroy");
        if (real_fa_destroy) real_fa_destroy(&linux_fa);
        if (real_attr_destroy) real_attr_destroy(&linux_attr);
    }
    return ret;
}

int macify_posix_spawn(void *pid, const char *path, const void *fa,
                       const void *attrp, char *const argv[], char *const envp[]) __asm__("posix_spawn");
int macify_posix_spawn(void *pid, const char *path, const void *fa,
                       const void *attrp, char *const argv[], char *const envp[]) {
    return do_posix_spawn((pid_t *)pid, path, fa, attrp, argv, envp, 0);
}

int macify_posix_spawnp(void *pid, const char *file, const void *fa,
                        const void *attrp, char *const argv[], char *const envp[]) __asm__("posix_spawnp");
int macify_posix_spawnp(void *pid, const char *file, const void *fa,
                        const void *attrp, char *const argv[], char *const envp[]) {
    return do_posix_spawn((pid_t *)pid, file, fa, attrp, argv, envp, 1);
}

/* ── exec family — translate paths and re-run through macify ────
 *
 * When a macOS binary calls execve("/bin/sh"), we need to:
 *   1. Translate the path: /bin/sh → <prefix>/bin/sh
 *   2. Check if the target is a Mach-O binary (magic 0xFEEDFACF)
 *   3. If Mach-O, transform to: execve(macify, {macify, target, args...}, env)
 *      because Linux can't exec Mach-O directly.
 *   4. If ELF, pass through normally.
 *
 * For execvp/execvpe (PATH search), search the translated PATH dirs
 * in the prefix.
 */

/* Check if a file is a Mach-O binary (not ELF) */
static int is_macho_binary(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t magic;
    ssize_t n = read(fd, &magic, sizeof(magic));
    close(fd);
    if (n != sizeof(magic)) return 0;
    /* Mach-O 64-bit magic (little-endian): 0xFEEDFACF */
    /* Mach-O 64-bit magic (big-endian): 0xCFFAEDFE */
    return (magic == 0xFEEDFACF || magic == 0xCFFAEDFE ||
            magic == 0xFEEDFACE || magic == 0xCEFAEDFE);
}

/* Get the path to the macify binary (from MACIFY_BINARY env or /proc/self/exe) */
static const char *get_macify_binary(void) {
    const char *mb = getenv("MACIFY_BINARY");
    if (mb && mb[0]) return mb;
    /* Fallback: /proc/self/exe points to the current process (macify) */
    static char exe_path[4096];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n > 0) {
        exe_path[n] = '\0';
        return exe_path;
    }
    return NULL;
}

/* Build a new argv array: {macify, target_path, original_argv[1]...} */
static char **build_macify_argv(const char *target, char *const argv[]) {
    /* Count original args */
    int argc = 0;
    if (argv) while (argv[argc]) argc++;
    /* Allocate: macify + target + original_args + NULL */
    char **new_argv = calloc(argc + 3, sizeof(char *));
    if (!new_argv) return NULL;
    new_argv[0] = (char *)"macify";
    new_argv[1] = (char *)target;
    for (int i = 1; i < argc; i++)
        new_argv[i + 1] = argv[i];
    new_argv[argc + 1] = NULL;
    return new_argv;
}

/* Resolve a filename via PATH search in the prefix.
 * Returns the full translated path in `out`, or NULL if not found. */
static int resolve_in_prefix_path(const char *file, char *out, size_t out_size) {
    if (!file || !file[0]) return -1;
    /* If file contains '/', it's already a path — translate it */
    if (strchr(file, '/')) {
        extern int macify_translate_path(const char *, char *, size_t);
        if (macify_translate_path(file, out, out_size) == 0)
            return 0;
        strncpy(out, file, out_size - 1);
        out[out_size - 1] = '\0';
        return 0;
    }
    /* Search PATH — use macOS-style PATH (/usr/bin:/bin:/usr/local/bin)
     * which gets translated to <prefix>/usr/bin, etc. */
    const char *path_env = getenv("PATH");
    if (!path_env) path_env = "/usr/bin:/bin:/usr/local/bin";
    char path_copy[4096];
    strncpy(path_copy, path_env, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    char *dir = strtok(path_copy, ":");
    while (dir) {
        char macos_path[4096];
        snprintf(macos_path, sizeof(macos_path), "%s/%s", dir, file);
        extern int macify_translate_path(const char *, char *, size_t);
        char translated[4096];
        if (macify_translate_path(macos_path, translated, sizeof(translated)) == 0) {
            if (access(translated, X_OK) == 0) {
                strncpy(out, translated, out_size - 1);
                out[out_size - 1] = '\0';
                return 0;
            }
        } else {
            /* Pass-through path (e.g., /dev) — check directly */
            if (access(macos_path, X_OK) == 0) {
                strncpy(out, macos_path, out_size - 1);
                out[out_size - 1] = '\0';
                return 0;
            }
        }
        dir = strtok(NULL, ":");
    }
    return -1;
}

/* execve — translate path, re-run through macify if Mach-O */
int macify_execve(const char *path, char *const argv[], char *const envp[]) __asm__("execve");
int macify_execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");

    if (!path) { errno = EFAULT; return -1; }

    /* Translate path */
    char translated[4096];
    extern int macify_translate_path(const char *, char *, size_t);
    const char *eff_path = path;
    if (macify_translate_path(path, translated, sizeof(translated)) == 0)
        eff_path = translated;

    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[512]; int n = snprintf(b, sizeof(b),
            "macify: execve(\"%s\" -> \"%s\")\n", path, eff_path);
        (void)write(2, b, n);
    }

    /* If it's a Mach-O binary, re-run through macify */
    if (is_macho_binary(eff_path)) {
        const char *macify_bin = get_macify_binary();
        if (macify_bin) {
            char **new_argv = build_macify_argv(eff_path, argv);
            if (new_argv) {
                int ret = real_execve ? real_execve(macify_bin, new_argv, envp) : -1;
                free(new_argv);
                return ret;
            }
        }
    }

    /* ELF or unknown — pass through */
    return real_execve ? real_execve(eff_path, argv, envp) : -1;
}

/* execvpe — PATH search + translate + re-run through macify if Mach-O */
int macify_execvp(const char *file, char *const argv[], char *const envp[]) __asm__("execvpe");
int macify_execvp(const char *file, char *const argv[], char *const envp[]) {
    if (!file) { errno = EFAULT; return -1; }

    /* Resolve file via PATH search in prefix */
    char resolved[4096];
    if (resolve_in_prefix_path(file, resolved, sizeof(resolved)) != 0) {
        errno = ENOENT;
        return -1;
    }

    /* If it's a Mach-O binary, re-run through macify using execve (not execvpe)
     * since we already have the full path. */
    if (is_macho_binary(resolved)) {
        const char *macify_bin = get_macify_binary();
        if (macify_bin) {
            char **new_argv = build_macify_argv(resolved, argv);
            if (new_argv) {
                static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
                if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");
                /* Make sure LD_LIBRARY_PATH is set so macify can find the shim */
                if (!getenv("LD_LIBRARY_PATH")) {
                    char libpath[4096];
                    strncpy(libpath, macify_bin, sizeof(libpath) - 1);
                    libpath[sizeof(libpath) - 1] = '\0';
                    char *slash = strrchr(libpath, '/');
                    if (slash) *slash = '\0';
                    setenv("LD_LIBRARY_PATH", libpath, 1);
                }
                int ret = real_execve ? real_execve(macify_bin, new_argv, envp) : -1;
                free(new_argv);
                return ret;
            }
        }
    }

    /* ELF or unknown — use real execvpe */
    static int (*real_execvpe)(const char *, char *const [], char *const []) = NULL;
    if (!real_execvpe) real_execvpe = dlsym(RTLD_NEXT, "execvpe");
    return real_execvpe ? real_execvpe(resolved, argv, envp) : -1;
}

/* execvp — same as execvpe but uses environ */
int macify_execvp2(const char *file, char *const argv[]) __asm__("execvp");
int macify_execvp2(const char *file, char *const argv[]) {
    extern char **environ;
    return macify_execvp(file, argv, environ);
}
