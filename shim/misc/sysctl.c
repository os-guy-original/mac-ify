/* sysctl.c — macOS sysctl/sysctlbyname/sysctlnametomib */
#include "../shim.h"
#include <sys/utsname.h>

/* sysctl — macOS system information query. Rust uses this for CPU count,
 * memory size, hostname, etc. We implement common queries using Linux
 * equivalents and return -1 for unknown queries. */
#include <sys/utsname.h>

int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
           void *newp, size_t newlen) {
    (void)newp; (void)newlen;
    if (!name || namelen == 0) return -1;

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
        /* KERN_OSTYPE=1, KERN_HOSTNAME=10, KERN_OSRELEASE=2 */
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
