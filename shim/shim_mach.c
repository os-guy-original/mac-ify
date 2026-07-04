#include "shim.h"
#include <sys/utsname.h>

/* ── Mach message/trap stubs ──────────────────────────────────── */

int mach_msg(void *msg, int option, uint32_t send_size,
             uint32_t rcv_size, int rcv_name, int timeout, int notify) {
    (void)msg; (void)option; (void)send_size; (void)rcv_size;
    (void)rcv_name; (void)timeout; (void)notify;
    return 0x10000003;
}

/* ── Mach port/task/host stubs ────────────────────────────────── */

uint32_t mach_task_self(void) { return 0x1000; }
uint32_t mach_task_self_(void) { return 0x1000; }
uint32_t mach_thread_self(void) { return 0x2000; }
uint32_t mach_host_self(void) { return 0x3000; }

int mach_port_deallocate(uint32_t task, uint32_t name) {
    (void)task; (void)name;
    return 0;
}

int mach_port_allocate(uint32_t task, int alloc_type, uint32_t *name) {
    (void)task; (void)alloc_type;
    if (name) *name = 0x4000;
    return 0;
}

int mach_port_insert_right(uint32_t task, uint32_t name, uint32_t right, int msgt) {
    (void)task; (void)name; (void)right; (void)msgt;
    return 0;
}

/* ── VM (virtual memory) stubs ────────────────────────────────── */

/* vm_page_size — global variable (not a function). htop reads this. */
uint32_t vm_page_size = 4096;

int vm_region_64(uint32_t target_task, uint32_t *address, uint32_t *size,
                 int flavor, void *info, int *count) {
    (void)target_task; (void)flavor; (void)info;
    if (address) *address = 0;
    if (size) *size = 0;
    if (count) *count = 0;
    return 5;  /* KERN_FAILURE */
}

int vm_allocate(uint32_t target_task, uint32_t *address, uint32_t size, int flags) {
    (void)target_task; (void)flags;
    void *r = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED) return 5;
    if (address) *address = (uint32_t)(uintptr_t)r;
    return 0;
}

int vm_deallocate(uint32_t target_task, uint64_t address, uint64_t size) {
    (void)target_task;
    if (size == 0 || address == 0) return 0;
    /* htop calls vm_deallocate on memory returned by host_processor_info,
     * which we allocate with malloc(). Try munmap first, and if it fails,
     * try free(). */
    if (munmap((void *)(uintptr_t)address, size) != 0) {
        free((void *)(uintptr_t)address);
    }
    return 0;
}

/* ── Mach time functions ──────────────────────────────────────── */

unsigned long long mach_absolute_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

typedef struct { uint32_t numer; uint32_t denom; } mach_timebase_info_data_t;

int mach_timebase_info(mach_timebase_info_data_t *info) {
    if (info) { info->numer = 1; info->denom = 1; }
    return 0;
}

/* ── Clock service stubs ──────────────────────────────────────── */

int host_get_clock_service(uint32_t host, int clock_id, uint32_t *clock_service) {
    (void)host; (void)clock_id;
    if (clock_service) *clock_service = 0x5000;
    return 0;
}

int clock_get_time(uint32_t clock_service, void *ts) {
    (void)clock_service;
    if (ts) {
        struct timespec linux_ts;
        clock_gettime(CLOCK_MONOTONIC, &linux_ts);
        int32_t *p = (int32_t *)ts;
        p[0] = (int32_t)linux_ts.tv_sec;
        p[1] = (int32_t)linux_ts.tv_nsec;
    }
    return 0;
}

/* ── Host statistics ──────────────────────────────────────────── */

#define CPU_STATE_USER   0
#define CPU_STATE_SYSTEM 1
#define CPU_STATE_NICE   2
#define CPU_STATE_IDLE   3

int host_statistics64(uint32_t host_priv, int flavor, void *host_info64_out,
                      uint32_t *count) {
    (void)host_priv;
    if (!host_info64_out || !count) return 1;

    if (flavor == 3) { /* HOST_CPU_LOAD_INFO */
        uint32_t *ticks = (uint32_t *)host_info64_out;
        memset(ticks, 0, 4 * sizeof(uint32_t));
        FILE *fp = fopen("/proc/stat", "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                unsigned long user, nice, system, idle;
                if (sscanf(line, "cpu %lu %lu %lu %lu",
                           &user, &nice, &system, &idle) == 4) {
                    ticks[CPU_STATE_USER] = (uint32_t)user;
                    ticks[CPU_STATE_SYSTEM] = (uint32_t)system;
                    ticks[CPU_STATE_NICE] = (uint32_t)nice;
                    ticks[CPU_STATE_IDLE] = (uint32_t)idle;
                }
            }
            fclose(fp);
        }
        *count = 4;
        return 0;
    }

    if (flavor == 4) { /* HOST_VM_INFO64 */
        memset(host_info64_out, 0, *count * sizeof(uint32_t));
        uint32_t *v = (uint32_t *)host_info64_out;
        FILE *fp = fopen("/proc/meminfo", "r");
        if (fp) {
            char line[256];
            unsigned long mem_free = 0, mem_active = 0, mem_inactive = 0;
            unsigned long mem_total = 0, buffers = 0, cached = 0;
            while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "MemTotal: %lu kB", &mem_total)) {}
                else if (sscanf(line, "MemFree: %lu kB", &mem_free)) {}
                else if (sscanf(line, "Active: %lu kB", &mem_active)) {}
                else if (sscanf(line, "Inactive: %lu kB", &mem_inactive)) {}
                else if (sscanf(line, "Buffers: %lu kB", &buffers)) {}
                else if (sscanf(line, "Cached: %lu kB", &cached)) {}
            }
            fclose(fp);
            v[0] = (uint32_t)(mem_free / 4);
            v[1] = (uint32_t)(mem_active / 4);
            v[2] = (uint32_t)(mem_inactive / 4);
            v[3] = (uint32_t)((mem_total - mem_free - mem_active - mem_inactive - buffers - cached) / 4);
        }
        *count = 18;
        return 0;
    }

    if (flavor == 2) { /* HOST_VM_INFO */
        memset(host_info64_out, 0, *count * sizeof(uint32_t));
        uint32_t *v = (uint32_t *)host_info64_out;
        FILE *fp = fopen("/proc/meminfo", "r");
        if (fp) {
            char line[256];
            unsigned long mem_free = 0, mem_active = 0, mem_inactive = 0, mem_total = 0;
            while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "MemTotal: %lu kB", &mem_total)) {}
                else if (sscanf(line, "MemFree: %lu kB", &mem_free)) {}
                else if (sscanf(line, "Active: %lu kB", &mem_active)) {}
                else if (sscanf(line, "Inactive: %lu kB", &mem_inactive)) {}
            }
            fclose(fp);
            v[0] = (uint32_t)(mem_free / 4);
            v[1] = (uint32_t)(mem_active / 4);
            v[2] = (uint32_t)(mem_inactive / 4);
            v[3] = (uint32_t)((mem_total - mem_free - mem_active - mem_inactive) / 4);
        }
        *count = 14;
        return 0;
    }

    return 1;
}

int host_statistics(uint32_t host_priv, int flavor, void *host_info_out,
                    uint32_t *count) {
    return host_statistics64(host_priv, flavor, host_info_out, count);
}

/* ── host_processor_info ──────────────────────────────────────── */

int host_processor_info(uint32_t host, int flavor, uint32_t *out_processor_count,
                        uint32_t **out_processor_info, uint32_t *out_processor_info_cnt) {
    (void)host;
    if (flavor != 2) return 1; /* PROCESSOR_CPU_LOAD_INFO */

    int ncpu = 0;
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) {
        if (out_processor_count) *out_processor_count = 1;
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == 'c' && line[1] == 'p' && line[2] == 'u' && line[3] >= '0' && line[3] <= '9')
            ncpu++;
    }
    fclose(fp);
    if (ncpu == 0) ncpu = 1;

    /* Use static buffer to avoid vm_deallocate issues */
    static uint32_t *info = NULL;
    static int prev_ncpu = 0;
    if (!info || prev_ncpu != ncpu) {
        if (info) free(info);
        info = (uint32_t *)malloc(ncpu * 4 * sizeof(uint32_t));
        if (!info) return 2;
        prev_ncpu = ncpu;
    }
    memset(info, 0, ncpu * 4 * sizeof(uint32_t));

    fp = fopen("/proc/stat", "r");
    if (fp) {
        int cpu_idx = 0;
        while (fgets(line, sizeof(line), fp) && cpu_idx < ncpu) {
            if (line[0] == 'c' && line[1] == 'p' && line[2] == 'u' && line[3] >= '0' && line[3] <= '9') {
                unsigned long user, nice, system, idle;
                if (sscanf(line, "cpu%*d %lu %lu %lu %lu",
                           &user, &nice, &system, &idle) == 4) {
                    info[cpu_idx * 4 + CPU_STATE_USER] = (uint32_t)user;
                    info[cpu_idx * 4 + CPU_STATE_SYSTEM] = (uint32_t)system;
                    info[cpu_idx * 4 + CPU_STATE_NICE] = (uint32_t)nice;
                    info[cpu_idx * 4 + CPU_STATE_IDLE] = (uint32_t)idle;
                }
                cpu_idx++;
            }
        }
        fclose(fp);
    }

    if (out_processor_count) *out_processor_count = (uint32_t)ncpu;
    if (out_processor_info) *out_processor_info = info;
    if (out_processor_info_cnt) *out_processor_info_cnt = (uint32_t)(ncpu * 4);
    return 0;
}

/* ── host_info ────────────────────────────────────────────────── */

typedef struct {
    int32_t max_cpus;
    int32_t avail_cpus;
    int32_t memory_size;
    int32_t cpu_type;
    int32_t cpu_subtype;
    uint32_t cpu_threadtype;
    int32_t physical_cpu;
    int32_t physical_cpu_max;
    int32_t logical_cpu;
    int32_t logical_cpu_max;
    uint64_t max_mem;
} host_basic_info_data_t;

int host_info(uint32_t host, int flavor, void *host_info_out, uint32_t *count) {
    (void)host;
    if (!host_info_out || !count) return 1;

    if (flavor == 1) { /* HOST_BASIC_INFO */
        host_basic_info_data_t *info = (host_basic_info_data_t *)host_info_out;
        memset(info, 0, sizeof(*info));
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        long phycpu = sysconf(_SC_NPROCESSORS_CONF);
        long pagesize = sysconf(_SC_PAGESIZE);
        long pages = sysconf(_SC_PHYS_PAGES);
        info->max_cpus = (int32_t)ncpu;
        info->avail_cpus = (int32_t)ncpu;
        info->physical_cpu = (int32_t)phycpu;
        info->physical_cpu_max = (int32_t)phycpu;
        info->logical_cpu = (int32_t)ncpu;
        info->logical_cpu_max = (int32_t)ncpu;
        info->memory_size = (int32_t)(pagesize * pages / 1024);
        info->max_mem = (uint64_t)pagesize * (uint64_t)pages;
        info->cpu_type = 0x01000007;  /* CPU_TYPE_X86_64 */
        info->cpu_subtype = 3;
        *count = sizeof(host_basic_info_data_t) / sizeof(uint32_t);
        return 0;
    }
    return 1;
}

/* ── Task/thread stubs ────────────────────────────────────────── */

int task_for_pid(uint32_t target_task, int pid, uint32_t *task) {
    (void)target_task;
    if (task) *task = (uint32_t)(0x10000 | (pid & 0xFFFF));
    return 0;
}

int task_threads(uint32_t target_task, uint32_t **act_list, uint32_t *count) {
    (void)target_task;
    if (act_list) {
        *act_list = (uint32_t *)malloc(sizeof(uint32_t));
        if (*act_list) **act_list = 0x20000;
    }
    if (count) *count = 1;
    return 0;
}

typedef struct {
    int32_t user_time_seconds;
    int32_t user_time_microseconds;
    int32_t system_time_seconds;
    int32_t system_time_microseconds;
    int32_t cpu_usage;
    int32_t policy;
    int32_t run_state;
    int32_t flags;
    int32_t suspend_count;
    int32_t sleep_time;
} thread_basic_info_data_t;

int thread_info(uint32_t thread, int flavor, void *thread_info_out, uint32_t *count) {
    (void)thread;
    if (flavor == 3) { /* THREAD_BASIC_INFO */
        thread_basic_info_data_t *info = (thread_basic_info_data_t *)thread_info_out;
        memset(info, 0, sizeof(*info));
        info->run_state = 1;
        *count = sizeof(thread_basic_info_data_t) / sizeof(int32_t);
        return 0;
    }
    return 1;
}

/* ── proc_pidpath / proc_pidinfo ──────────────────────────────── */

int proc_pidpath(int pid, void *buffer, uint32_t buffersize) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, (char *)buffer, buffersize - 1);
    if (len < 0) {
        if (pid == getpid()) {
            len = readlink("/proc/self/exe", (char *)buffer, buffersize - 1);
        }
    }
    if (len < 0) {
        if (buffersize > 0) ((char *)buffer)[0] = '\0';
        return 0;
    }
    ((char *)buffer)[len] = '\0';
    return (int)len;
}

int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    (void)arg;
    if (!buffer || buffersize <= 0) return 0;
    memset(buffer, 0, buffersize);

    if (flavor == 4) { /* PROC_PIDTASKINFO */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE *fp = fopen(path, "r");
        if (fp) {
            char line[1024];
            if (fgets(line, sizeof(line), fp)) {
                char *p = strchr(line, ')');
                if (p) {
                    p += 2;
                    char state;
                    int ppid, pgrp, session, tty_nr, tpgid;
                    unsigned long flags, minflt, cminflt, majflt, cmajflt;
                    unsigned long utime, stime, cutime, cstime;
                    int priority, nice, threads, itrealvalue;
                    unsigned long long starttime;
                    unsigned long vsize;
                    long rss;
                    if (sscanf(p, "%c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %d %d %llu %lu %ld",
                               &state, &ppid, &pgrp, &session, &tty_nr, &tpgid,
                               &flags, &minflt, &cminflt, &majflt, &cmajflt,
                               &utime, &stime, &cutime, &cstime,
                               &priority, &nice, &threads, &itrealvalue,
                               &starttime, &vsize, &rss) >= 21) {
                        uint64_t *pti = (uint64_t *)buffer;
                        pti[0] = vsize;
                        pti[1] = (uint64_t)rss * 4096;
                        pti[2] = utime * 10000;
                        pti[3] = stime * 10000;
                        pti[4] = 0;
                        pti[5] = 0;
                        int32_t *pti32 = (int32_t *)(pti + 6);
                        pti32[0] = 0;
                        pti32[1] = (int32_t)(minflt + majflt);
                        pti32[2] = (int32_t)majflt;
                        pti32[3] = 0;
                        pti32[4] = 0;
                        pti32[5] = 0;
                        pti32[6] = 0;
                        pti32[7] = 0;
                        pti32[8] = 0;
                        pti32[9] = threads;
                        pti32[10] = 1;
                        pti32[11] = priority;
                    }
                }
            }
            fclose(fp);
            return buffersize;
        }
    }
    return 0;
}

/* ── devname_r ────────────────────────────────────────────────── */

int devname_r(uint32_t dev, int type, char *buf, int len) {
    (void)dev; (void)type;
    if (buf && len > 0) {
        snprintf(buf, len, "tty");
    }
    return 0;
}

/* ── proc_listpids ────────────────────────────────────────────── */

int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    (void)type; (void)typeinfo;
    DIR *dir = opendir("/proc");
    if (!dir) {
        if (buffer && buffersize > 0) ((int *)buffer)[0] = 0;
        return 0;
    }
    int *pids = (int *)buffer;
    int count = 0;
    int max_pids = buffersize / sizeof(int);
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        int is_pid = 1;
        for (int i = 0; ent->d_name[i]; i++) {
            if (ent->d_name[i] < '0' || ent->d_name[i] > '9') { is_pid = 0; break; }
        }
        if (is_pid && ent->d_name[0] != '\0') {
            if (count < max_pids) {
                pids[count] = atoi(ent->d_name);
            }
            count++;
        }
    }
    closedir(dir);
    return count * sizeof(int);
}

int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize) {
    (void)pid; (void)fd; (void)flavor; (void)buffer; (void)buffersize;
    return 0;
}

int proc_pid_rusage(int pid, int flavor, void *buffer) {
    (void)pid; (void)flavor; (void)buffer;
    return 0;
}
