/* syscall_names.c — BSD syscall name lookup for debug output */
#include "syscall_internal.h"

#define BSD_SYSCALL_MAX 600

/* BSD syscall names for nicer verbose output. */
const char *bsd_syscall_name(uint32_t bsd_nr) {
    switch (bsd_nr) {
        case 1:   return "exit";
        case 2:   return "fork";
        case 3:   return "read";
        case 4:   return "write";
        case 5:   return "open";
        case 6:   return "close";
        case 7:   return "wait4";
        case 9:   return "link";
        case 10:  return "unlink";
        case 12:  return "chdir";
        case 13:  return "fchdir";
        case 14:  return "mknod";
        case 15:  return "chmod";
        case 16:  return "chown";
        case 20:  return "getpid";
        case 23:  return "setuid";
        case 24:  return "getuid";
        case 25:  return "geteuid";
        case 27:  return "recvmsg";
        case 28:  return "sendmsg";
        case 29:  return "recvfrom";
        case 30:  return "accept";
        case 31:  return "getpeername";
        case 32:  return "getsockname";
        case 33:  return "access";
        case 36:  return "sync";
        case 37:  return "kill";
        case 39:  return "getppid";
        case 41:  return "pipe";
        case 42:  return "pipe";
        case 43:  return "getegid";
        case 46:  return "sigaction";
        case 47:  return "getgid";
        case 48:  return "sigprocmask";
        case 53:  return "sigaltstack";
        case 54:  return "ioctl";
        case 57:  return "symlink";
        case 58:  return "readlink";
        case 59:  return "execve";
        case 60:  return "umask";
        case 61:  return "chroot";
        case 65:  return "msync";
        case 73:  return "munmap";
        case 74:  return "mprotect";
        case 75:  return "madvise";
        case 78:  return "mincore";
        case 79:  return "getgroups";
        case 80:  return "setgroups";
        case 81:  return "getpgrp";
        case 82:  return "setpriority";
        case 83:  return "getpriority";
        case 89:  return "getitimer";
        case 90:  return "setitimer";
        case 92:  return "fcntl";
        case 93:  return "select";
        case 95:  return "fsync";
        case 97:  return "socket";
        case 98:  return "connect";
        case 116: return "gettimeofday";
        case 117: return "getrusage";
        case 118: return "getsockopt";
        case 120: return "readv";
        case 121: return "writev";
        case 126: return "settimeofday";
        case 128: return "rename";
        case 131: return "flock";
        case 133: return "sendto";
        case 134: return "shutdown";
        case 135: return "socketpair";
        case 136: return "mkdir";
        case 137: return "rmdir";
        case 138: return "utimes";
        case 197: return "mmap";
        case 199: return "lseek";
        case 200: return "truncate";
        case 201: return "ftruncate";
        case 202: return "nanosleep";
        case 220: return "getxattr";
        case 221: return "fgetxattr";
        case 222: return "setxattr";
        case 223: return "fsetxattr";
        case 224: return "removexattr";
        case 225: return "fremovexattr";
        case 226: return "listxattr";
        case 227: return "llistxattr";
        case 228: return "flistxattr";
        case 286: return "pwrite";
        case 287: return "pread";
        case 331: return "fchown";
        case 333: return "fchmod";
        case 396: return "read_nocancel";
        case 397: return "write_nocancel";
        case 398: return "open_nocancel";
        case 399: return "close_nocancel";
        case 400: return "wait4_nocancel";
        case 401: return "recvmsg_nocancel";
        case 402: return "sendmsg_nocancel";
        case 403: return "recvfrom_nocancel";
        case 404: return "accept_nocancel";
        case 405: return "fcntl_nocancel";
        case 406: return "select_nocancel";
        case 460: return "pread";
        case 461: return "pwrite";
        case 465: return "pread_nocancel";
        case 466: return "pwrite_nocancel";
        default:  return "?";
    }
}


