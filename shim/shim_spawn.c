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

static int do_posix_spawn(pid_t *pid, const char *path,
                          const void *file_actions, const void *attrp,
                          char *const argv[], char *const envp[],
                          int use_path) {
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
            if (real_spawnp) ret = real_spawnp(pid, path, &linux_fa, &linux_attr, argv, envp);
            else ret = ENOSYS;
        } else {
            if (!real_spawn) real_spawn = dlsym(RTLD_NEXT, "posix_spawn");
            if (real_spawn) ret = real_spawn(pid, path, &linux_fa, &linux_attr, argv, envp);
            else ret = ENOSYS;
        }
    }

    posix_spawn_file_actions_destroy(&linux_fa);
    posix_spawnattr_destroy(&linux_attr);
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
