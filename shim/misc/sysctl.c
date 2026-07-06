/* sysctl.c — macOS sysctl/sysctlbyname/sysctlnametomib */
#include "../shim.h"
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>    /* gettimeofday, struct timeval */

/* sysctl — macOS system information query. Rust uses this for CPU count,
 * memory size, hostname, etc. We implement common queries using Linux
 * equivalents and return -1 for unknown queries. */
#include <sys/utsname.h>

/* macOS KERN_PROC constants */
#define CTL_KERN           1
#define KERN_PROC         14
#define KERN_PROC_ALL      0
#define KERN_PROC_PID      1

/* macOS kinfo_proc field offsets (determined by disassembling htop's
 * DarwinProcess_setFromKInfoProc). The total struct is 648 bytes. */
#define KINFO_PROC_SIZE    648
#define KP_P_FLAG         0x20   /* int32: p_flag */
#define KP_P_PID          0x28   /* int32: p_pid */
#define KP_P_STAT         0xf0   /* uint8: some status byte */
#define KP_P_STAT2        0xf2   /* uint8: another status byte */
#define KP_E_PPID         0x230  /* int32: e_ppid */
#define KP_E_PGID         0x234  /* int32: e_pgid */
#define KP_E_TDEV         0x23c  /* int32: e_tdev */
#define KP_E_TPGID        0x240  /* int32: e_tpgid */

int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
           void *newp, size_t newlen) {
    (void)newp; (void)newlen;
    if (!name || namelen == 0) return -1;

    if (getenv("MACIFY_SYSCTL_DEBUG")) {
        char b[256];
        int n = snprintf(b, sizeof(b), "macify: sysctl(name=[");
        for (u_int i = 0; i < namelen && n < 240; i++) {
            n += snprintf(b+n, sizeof(b)-n, "%d%s", name[i], i+1<namelen?",":"");
        }
        n += snprintf(b+n, sizeof(b)-n, "], namelen=%u, oldp=%p, oldlen=%zu)\n",
                namelen, oldp, oldlenp ? *oldlenp : 0);
        (void)write(2, b, n);
    }

    int sysctl_ret = -1;  /* will be set to actual return value */

    /* CTL_UNSPEC=0, CTL_KERN=1, CTL_HW=6, CTL_USER=8, CTL_VM=2 */
    int top = name[0];

    if (top == 6) {  /* CTL_HW */
        if (namelen < 2) return -1;
        int id = name[1];
        /* HW_NCPU=3, HW_MEMSIZE=24, HW_PAGESIZE=7 */
        if (id == 3) {  /* HW_NCPU */
            int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
            if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
                *(int *)oldp = ncpu;
                *oldlenp = sizeof(int);
            }
            return 0;
        }
        if (id == 24) {  /* HW_MEMSIZE */
            if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
                long pages = sysconf(_SC_PHYS_PAGES);
                long page_size = sysconf(_SC_PAGESIZE);
                *(uint64_t *)oldp = (uint64_t)pages * page_size;
                *oldlenp = sizeof(uint64_t);
            }
            return 0;
        }
        if (id == 7) {  /* HW_PAGESIZE */
            if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
                *(int *)oldp = (int)sysconf(_SC_PAGESIZE);
                *oldlenp = sizeof(int);
            }
            return 0;
        }
    }

    if (top == 1) {  /* CTL_KERN */
        if (namelen < 2) return -1;
        int id = name[1];

        /* KERN_PROC — process listing. htop uses sysctl(KERN_PROC_ALL) to
         * get all processes as an array of kinfo_proc structs. */
        if (id == 14) {  /* KERN_PROC */
            int which = (namelen >= 3) ? name[2] : 0;

            /* TEMPORARY: return 0 processes to test if crash is from kinfo_proc data */
            if (getenv("MACIFY_NO_PROCS")) {
                if (!oldp) {
                    if (oldlenp) *oldlenp = 0;
                    return 0;
                }
                if (oldlenp) *oldlenp = 0;
                return 0;
            }

            /* Count processes by reading /proc */
            DIR *dir = opendir("/proc");
            if (!dir) { errno = ENOENT; return -1; }
            int count = 0;
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL) {
                int is_pid = 1;
                for (int i = 0; ent->d_name[i]; i++) {
                    if (ent->d_name[i] < '0' || ent->d_name[i] > '9') {
                        is_pid = 0; break;
                    }
                }
                if (is_pid && ent->d_name[0] != '\0') count++;
            }
            closedir(dir);

            size_t needed = (size_t)count * KINFO_PROC_SIZE;
            if (!oldp) {
                /* First call: just return the size */
                if (oldlenp) *oldlenp = needed;
                return 0;
            }
            if (!oldlenp) { errno = EFAULT; return -1; }
            if (*oldlenp < needed) { errno = ENOMEM; return -1; }

            /* Second call: fill in kinfo_proc array from /proc/PID/stat */
            memset(oldp, 0, needed);
            uint8_t *out = (uint8_t *)oldp;
            dir = opendir("/proc");
            if (!dir) { errno = ENOENT; return -1; }
            int idx = 0;
            while ((ent = readdir(dir)) != NULL && idx < count) {
                int is_pid = 1;
                for (int i = 0; ent->d_name[i]; i++) {
                    if (ent->d_name[i] < '0' || ent->d_name[i] > '9') {
                        is_pid = 0; break;
                    }
                }
                if (!is_pid || ent->d_name[0] == '\0') continue;

                int pid = atoi(ent->d_name);
                uint8_t *kp = out + (size_t)idx * KINFO_PROC_SIZE;

                /* Write PID */
                *(int32_t *)(kp + KP_P_PID) = pid;

                /* Read /proc/PID/stat for more fields */
                char path[64];
                snprintf(path, sizeof(path), "/proc/%d/stat", pid);
                FILE *fp_stat = fopen(path, "r");
                if (fp_stat) {
                    char line[1024];
                    if (fgets(line, sizeof(line), fp_stat)) {
                        /* Parse: pid (comm) state ppid pgrp session tty_nr tpgid
                         *        flags ... utime stime ... vsize rss */
                        /* Find last ')' to skip comm */
                        char *p = strrchr(line, ')');
                        if (p) {
                            p += 2;
                            char state;
                            int ppid, pgrp, session, tty_nr, tpgid;
                            unsigned long flags;
                            unsigned long utime, stime;
                            unsigned long vsize;
                            long rss;
                            if (sscanf(p, "%c %d %d %d %d %d %lu",
                                       &state, &ppid, &pgrp, &session,
                                       &tty_nr, &tpgid, &flags) >= 7) {
                                *(int32_t *)(kp + KP_E_PPID) = ppid;
                                *(int32_t *)(kp + KP_E_PGID) = pgrp;
                                *(int32_t *)(kp + KP_E_TDEV) = tty_nr;
                                *(int32_t *)(kp + KP_E_TPGID) = tpgid;
                                *(int32_t *)(kp + KP_P_FLAG) = (int32_t)flags;
                                /* Map Linux state to macOS p_stat */
                                /* macOS: SRUN=2, SSLEEP=3, SSTOP=4, SZOMB=5, SIDL=1 */
                                uint8_t mac_stat = 3; /* default: SSLEEP */
                                switch (state) {
                                    case 'R': mac_stat = 2; break; /* SRUN */
                                    case 'S': mac_stat = 3; break; /* SSLEEP */
                                    case 'D': mac_stat = 3; break; /* uninterruptible sleep -> SSLEEP */
                                    case 'Z': mac_stat = 5; break; /* SZOMB */
                                    case 'T': mac_stat = 4; break; /* SSTOP */
                                    case 'I': mac_stat = 1; break; /* SIDL */
                                }
                                *(uint8_t *)(kp + KP_P_STAT) = mac_stat;
                            }
                        }
                    }
                    fclose(fp_stat);
                }
                idx++;
            }
            closedir(dir);
            *oldlenp = needed;
            return 0;
        }

        /* KERN_OSTYPE=1, KERN_HOSTNAME=10, KERN_OSRELEASE=2, KERN_BOOTTIME=8 */
        if (id == 8) {  /* KERN_BOOTTIME — struct timeval (16 bytes on x86_64) */
            if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                struct timeval tv;
                gettimeofday(&tv, NULL);
                /* Return boot time = current time - uptime */
                FILE *fp = fopen("/proc/uptime", "r");
                if (fp) {
                    double uptime = 0;
                    if (fscanf(fp, "%lf", &uptime) == 1) {
                        tv.tv_sec -= (time_t)uptime;
                    }
                    fclose(fp);
                }
                memcpy(oldp, &tv, sizeof(tv));
                *oldlenp = sizeof(tv);
            }
            return 0;
        }
        if (id == 49) {  /* KERN_PROCARGS2 — process arguments */
            /* name[2] = pid. Returns: 4-byte argc, then argc null-terminated
             * strings (the process arguments). */
            if (namelen < 3) { errno = EINVAL; return -1; }
            int pid = name[2];
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            FILE *fp = fopen(path, "rb");
            if (!fp) { errno = ENOENT; return -1; }
            /* Read the cmdline raw (null-separated args) */
            char buf[65536];
            size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
            fclose(fp);
            /* Count args */
            int argc = 0;
            size_t pos = 0;
            while (pos < nread) {
                argc++;
                pos += strlen(buf + pos) + 1;
            }
            /* Total size: 4 (argc) + nread (args) */
            size_t total = 4 + nread;
            if (!oldp) {
                if (oldlenp) *oldlenp = total;
                return 0;
            }
            if (!oldlenp || *oldlenp < total) { errno = ENOMEM; return -1; }
            /* Write argc (4 bytes, host-endian/little-endian on x86_64) */
            uint32_t le_argc = (uint32_t)argc;
            memcpy(oldp, &le_argc, 4);
            memcpy((char *)oldp + 4, buf, nread);
            *oldlenp = total;
            return 0;
        }
        if (id == 1 || id == 2) {  /* KERN_OSTYPE / KERN_OSRELEASE */
            struct utsname uts;
            uname(&uts);
            const char *val = (id == 1) ? "Darwin" : uts.release;
            size_t len = strlen(val) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp < len) return -1;  /* ENOMEM */
                strcpy((char *)oldp, val);
                *oldlenp = len;
            } else if (oldlenp) {
                *oldlenp = len;
            }
            return 0;
        }
        if (id == 10) {  /* KERN_HOSTNAME */
            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            size_t len = strlen(hostname) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp < len) return -1;
                strcpy((char *)oldp, hostname);
                *oldlenp = len;
            } else if (oldlenp) {
                *oldlenp = len;
            }
            return 0;
        }
    }

    /* Unknown sysctl — return -1 (errno will be ENOENT) */
    errno = ENOENT;
    return -1;
}

/* sysctlbyname — macOS variant that takes a string name instead of int array. */
int sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                 void *newp, size_t newlen) {
    (void)newp; (void)newlen;
    if (!name) return -1;

    /* Handle common Rust runtime queries */
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0) {
        int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int *)oldp = ncpu;
            *oldlenp = sizeof(int);
        }
        return 0;
    }
    if (strcmp(name, "hw.memsize") == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
            long pages = sysconf(_SC_PHYS_PAGES);
            long page_size = sysconf(_SC_PAGESIZE);
            *(uint64_t *)oldp = (uint64_t)pages * page_size;
            *oldlenp = sizeof(uint64_t);
        }
        return 0;
    }
    if (strcmp(name, "hw.pagesize") == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int *)oldp = (int)sysconf(_SC_PAGESIZE);
            *oldlenp = sizeof(int);
        }
        return 0;
    }

    errno = ENOENT;
    return -1;
}

/* sysctlnametomib — convert a sysctl name string to its MIB integer array.
 * We don't implement MIB lookup; return -1 (ENOENT). */
int sysctlnametomib(const char *name, int *mibp, size_t *sizep) {
    (void)name; (void)mibp; (void)sizep;
    errno = ENOENT;
    return -1;
}
