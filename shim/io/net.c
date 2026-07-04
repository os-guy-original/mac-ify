/* net.c — network: select, poll, getaddrinfo, socket, connect, bind,
 * sendto, recv, accept, getsockname, inet_ntop, inet_pton, writev, readv */
#include "io_internal.h"
#include <sys/select.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* macOS struct timeval layout (x86_64):
 *   offset 0:  tv_sec   (long — 8 bytes)
 *   offset 8:  tv_usec  (long — 8 bytes)
 * Total: 16 bytes, tv_usec is 8 bytes.
 *
 * If we pass the macOS struct directly to glibc's select, glibc reads
 * tv_usec as a 64-bit long, picking up 4 bytes of uninitialized padding
 * (or adjacent stack data). The garbage high 32 bits make tv_usec a
 * gigantic number, and the kernel's select sleeps for billions of years
 * — exactly the "hang" we observe during the GnuTLS handshake when wget
 * calls select() to wait for readability. Translate the struct. */
struct macos_timeval {
    long       tv_sec;    /* 8 bytes */
    int32_t    tv_usec;   /* 4 bytes (macOS: __int32_t) */
    /* implicit 4-byte padding */
};

int macify_select(int nfds, void *readfds, void *writefds, void *exceptfds,
                  void *timeout) __asm__("select");
int macify_select(int nfds, void *readfds, void *writefds, void *exceptfds,
                  void *timeout) {
    if (macify_net_debug_enabled < 0) {
        const char *e = getenv("MACIFY_NET_DEBUG");
        macify_net_debug_enabled = (e && e[0]) ? 1 : 0;
    }
    /* Convert macOS struct timeval → Linux struct timeval. */
    struct timeval linux_tv;
    struct timeval *linux_tv_ptr = NULL;
    if (timeout) {
        struct macos_timeval *mtv = (struct macos_timeval *)timeout;
        linux_tv.tv_sec  = (time_t)mtv->tv_sec;
        linux_tv.tv_usec = (suseconds_t)mtv->tv_usec;
        linux_tv_ptr = &linux_tv;
        if (macify_net_debug_enabled) {
            char b[256];
            snprintf(b, sizeof(b), "select: ENTER nfds=%d macos_tv=%ld.%d linux_tv=%ld.%ld\n",
                     nfds, (long)mtv->tv_sec, (int)mtv->tv_usec,
                     (long)linux_tv.tv_sec, (long)linux_tv.tv_usec);
            (void)write(2, b, strlen(b));
        }
    }
    static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = NULL;
    if (!real_select) real_select = dlsym(RTLD_NEXT, "__select");
    if (!real_select) return -1;
    int r = real_select(nfds, (fd_set *)readfds, (fd_set *)writefds,
                       (fd_set *)exceptfds, linux_tv_ptr);
    if (macify_net_debug_enabled) {
        char b[128];
        int saved = errno;
        snprintf(b, sizeof(b), "select: ret=%d errno=%d\n", r, saved);
        (void)write(2, b, strlen(b));
    }
    /* On return, copy the updated timeout back to the macOS struct
     * (select modifies the timeout to reflect the time not slept). */
    if (timeout && r >= 0) {
        struct macos_timeval *mtv = (struct macos_timeval *)timeout;
        mtv->tv_sec  = (long)linux_tv.tv_sec;
        mtv->tv_usec = (int32_t)linux_tv.tv_usec;
    }
    return r;
}

/* poll — glibc exports __poll, not poll. Same API on both platforms. */
int macify_poll(struct pollfd *fds, nfds_t nfds, int timeout) __asm__("poll");
int macify_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (macify_net_debug_enabled < 0) {
        const char *e = getenv("MACIFY_NET_DEBUG");
        macify_net_debug_enabled = (e && e[0]) ? 1 : 0;
    }
    if (macify_net_debug_enabled) {
        char b[256];
        snprintf(b, sizeof(b), "poll: ENTER nfds=%u timeout=%d [fd=%d events=0x%x]\n",
                 (unsigned)nfds, timeout, nfds > 0 ? fds[0].fd : -1, nfds > 0 ? fds[0].events : 0);
        (void)write(2, b, strlen(b));
    }
    static int (*real_poll)(struct pollfd *, nfds_t, int) = NULL;
    if (!real_poll) real_poll = dlsym(RTLD_NEXT, "__poll");
    if (!real_poll) return -1;
    int r = real_poll(fds, nfds, timeout);
    if (macify_net_debug_enabled < 0) {
        const char *e = getenv("MACIFY_NET_DEBUG");
        macify_net_debug_enabled = (e && e[0]) ? 1 : 0;
    }
    if (macify_net_debug_enabled && nfds > 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "poll: nfds=%u timeout=%d ret=%d [fd=%d events=0x%x revents=0x%x]\n",
                 (unsigned)nfds, timeout, r, fds[0].fd, fds[0].events, fds[0].revents);
        (void)write(2, buf, strlen(buf));
    }
    return r;
}

/* getaddrinfo — macOS struct addrinfo has a DIFFERENT layout from glibc's!
 *
 * glibc (Linux) addrinfo layout:
 *   offset 0:  ai_flags      (int)
 *   offset 4:  ai_family     (int)
 *   offset 8:  ai_socktype   (int)
 *   offset 12: ai_protocol   (int)
 *   offset 16: ai_addrlen    (socklen_t)
 *   offset 24: ai_addr       (struct sockaddr *)   <-- addr first
 *   offset 32: ai_canonname  (char *)
 *   offset 40: ai_next       (struct addrinfo *)
 *
 * macOS addrinfo layout (from <netdb.h>):
 *   offset 0:  ai_flags      (int)
 *   offset 4:  ai_family     (int)
 *   offset 8:  ai_socktype   (int)
 *   offset 12: ai_protocol   (int)
 *   offset 16: ai_addrlen    (socklen_t)
 *   offset 24: ai_canonname  (char *)               <-- canonname first
 *   offset 32: ai_addr       (struct sockaddr *)    <-- addr second (SWAPPED!)
 *   offset 40: ai_next       (struct addrinfo *)
 *
 * A macOS binary compiled against macOS headers reads ai_addr from offset 32.
 * If we return glibc's addrinfo as-is, it reads ai_canonname (typically NULL)
 * instead, then dereferences NULL+offset → SIGSEGV.
 *
 * Fix: rebuild the linked list with macOS layout (swap ai_canonname/ai_addr)
 * before returning to the macOS binary. We allocate the nodes ourselves so
 * freeaddrinfo must also be ours (not glibc's).
 *
 * glibc's getaddrinfo can also hang if NSS tries to communicate with nscd;
 * our fork/clone/wait4 stubs prevent that.
 *
 * The hints parameter is safe to pass as-is to glibc because glibc only reads
 * ai_flags, ai_family, ai_socktype, ai_protocol from hints (offsets 0–12,
 * which are identical in both layouts), and ignores the rest. */

/* macOS-layout addrinfo (canonname at offset 24, addr at offset 32). */
struct macos_addrinfo {
    int ai_flags;                  /* 0  */
    int ai_family;                 /* 4  */
    int ai_socktype;               /* 8  */
    int ai_protocol;               /* 12 */
    socklen_t ai_addrlen;          /* 16 */
    char *ai_canonname;            /* 24 — swapped vs Linux */
    struct sockaddr *ai_addr;      /* 32 — swapped vs Linux */
    struct macos_addrinfo *ai_next;/* 40 */
};

int macify_getaddrinfo(const char *node, const char *service,
                       const void *hints, void **res) __asm__("getaddrinfo");
int macify_getaddrinfo(const char *node, const char *service,
                       const void *hints, void **res) {
    macify_net_dbg("getaddrinfo: enter\n");
    static int (*real_gai)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
    if (!real_gai) real_gai = dlsym(RTLD_NEXT, "getaddrinfo");

    struct addrinfo *linux_res = NULL;
    int r = real_gai(node, service, (const struct addrinfo *)hints, &linux_res);
    char buf[256];

    if (r != 0 || !linux_res) {
        snprintf(buf, sizeof(buf), "getaddrinfo: ret=%d errno=%d\n", r, errno);
        macify_net_dbg(buf);
        if (res) *res = NULL;
        return r;
    }

    /* Rebuild the addrinfo linked list with macOS layout.
     * We allocate each node (and copies of sockaddr + canonname) ourselves
     * so freeaddrinfo can free them directly without invoking glibc. */
    struct macos_addrinfo *macos_head = NULL, *macos_tail = NULL;
    int node_count = 0;
    for (struct addrinfo *p = linux_res; p; p = p->ai_next) {
        struct macos_addrinfo *m = (struct macos_addrinfo *)malloc(sizeof(*m));
        if (!m) { r = EAI_MEMORY; break; }
        m->ai_flags    = p->ai_flags;
        m->ai_family   = p->ai_family;
        m->ai_socktype = p->ai_socktype;
        m->ai_protocol = p->ai_protocol;
        m->ai_addrlen  = p->ai_addrlen;
        m->ai_canonname = NULL;
        m->ai_addr     = NULL;
        m->ai_next     = NULL;

        /* Copy the sockaddr (we keep it in glibc's layout — the offsets of
         * sin_addr (4) and sin6_addr (8) / sin6_scope_id (24) are identical
         * in both Linux and macOS sockaddr layouts, so a macOS binary reading
         * address bytes via ai_addr works fine. If the binary later passes
         * ai_addr to connect(), the connect() shim auto-detects the format.) */
        if (p->ai_addr && p->ai_addrlen > 0) {
            void *addr_copy = malloc(p->ai_addrlen);
            if (addr_copy) {
                memcpy(addr_copy, p->ai_addr, p->ai_addrlen);
                m->ai_addr = (struct sockaddr *)addr_copy;
            }
        }
        if (p->ai_canonname) {
            size_t cn_len = strlen(p->ai_canonname) + 1;
            char *cn = (char *)malloc(cn_len);
            if (cn) {
                memcpy(cn, p->ai_canonname, cn_len);
                m->ai_canonname = cn;
            }
        }

        if (!macos_head) macos_head = m;
        else             macos_tail->ai_next = m;
        macos_tail = m;
        node_count++;
    }

    /* Free glibc's linked list — we no longer need it. */
    static void (*real_free)(struct addrinfo *) = NULL;
    if (!real_free) real_free = dlsym(RTLD_NEXT, "freeaddrinfo");
    real_free(linux_res);

    if (r != 0 && macos_head) {
        /* Allocation failed mid-way — free what we built. */
        struct macos_addrinfo *cur = macos_head;
        while (cur) {
            struct macos_addrinfo *next = cur->ai_next;
            free(cur->ai_canonname);
            free(cur->ai_addr);
            free(cur);
            cur = next;
        }
        if (res) *res = NULL;
        return r;
    }

    if (res) *res = macos_head;

    /* Debug: show the first result. Note: read ai_addr from offset 0x20 (32)
     * to confirm the macOS layout is correct. */
    if (macos_head) {
        struct macos_addrinfo *a = macos_head;
        uint8_t *ab = (uint8_t *)a->ai_addr;
        if (a->ai_family == 2 && a->ai_addr && a->ai_addrlen >= 8) {
            uint8_t *ip = ab + 4;
            snprintf(buf, sizeof(buf),
                     "getaddrinfo: ok family=%d ip=%u.%u.%u.%u port=%u (nodes=%d)\n",
                     a->ai_family, ip[0], ip[1], ip[2], ip[3],
                     (ab[2] << 8) | ab[3], node_count);
        } else {
            snprintf(buf, sizeof(buf),
                     "getaddrinfo: ok family=%d addrlen=%u (nodes=%d)\n",
                     a->ai_family, (unsigned)a->ai_addrlen, node_count);
        }
        macify_net_dbg(buf);
    }
    return r;
}

void macify_freeaddrinfo(void *ai) __asm__("freeaddrinfo");
void macify_freeaddrinfo(void *ai) {
    /* Free the macOS-layout addrinfo list that we allocated in
     * macify_getaddrinfo. We must NOT call glibc's freeaddrinfo because the
     * node layout is different (ai_canonname/ai_addr swapped) — glibc would
     * dereference offset 24 as ai_addr and try to free it, corrupting the
     * heap. */
    struct macos_addrinfo *cur = (struct macos_addrinfo *)ai;
    while (cur) {
        struct macos_addrinfo *next = cur->ai_next;
        free(cur->ai_canonname);
        free(cur->ai_addr);
        free(cur);
        cur = next;
    }
}

/* wait4 — allow for macOS callers (hyperfine needs it to wait for subprocesses).
 * Block for non-macOS (glibc NSS) to prevent deadlocks. */
/* fork/clone/wait4/read/write are in process.c */
/* setsockopt — macOS uses SO_NOSIGPIPE (0x1022) which doesn't exist on
 * Linux. Linux uses MSG_NOSIGNAL on send() instead. We intercept
 * setsockopt and silently ignore SO_NOSIGPIPE, translating it to a no-op.
 * Also translate other macOS-specific socket options. */


/* Translate macOS SOL_SOCKET optname to Linux optname.
 * macOS uses 0x1000-base for most options; Linux uses small integers.
 * Critical: SO_ERROR (macOS 0x1007 → Linux 4) — curl checks this
 * after non-blocking connect to determine if the connect succeeded. */
static int translate_sol_socket_optname(int optname) {
    switch (optname) {
        case 0x1:    return 1;     /* SO_DEBUG (same) */
        case 0x4:    return 2;     /* SO_REUSEADDR */
        case 0x8:    return 9;     /* SO_KEEPALIVE */
        case 0x10:   return 5;     /* SO_DONTROUTE */
        case 0x20:   return 6;     /* SO_BROADCAST */
        case 0x80:   return 13;    /* SO_LINGER */
        case 0x100:  return 10;    /* SO_OOBINLINE */
        case 0x200:  return 15;    /* SO_REUSEPORT */
        case 0x1001: return 7;     /* SO_SNDBUF */
        case 0x1002: return 8;     /* SO_RCVBUF */
        case 0x1003: return 19;    /* SO_SNDLOWAT */
        case 0x1004: return 18;    /* SO_RCVLOWAT */
        case 0x1005: return 47;    /* SO_SNDTIMEO */
        case 0x1006: return 20;    /* SO_RCVTIMEO */
        case 0x1007: return 4;     /* SO_ERROR */
        case 0x1008: return 3;     /* SO_TYPE */
        case 0x1016: return 38;    /* SO_PROTOCOL */
        case 0x1022: return -1;    /* SO_NOSIGPIPE — handled by caller (no-op) */
        default:     return optname; /* unknown, pass through */
    }
}

int macify_setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen) __asm__("setsockopt");
int macify_setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen) {
    /* macOS SOL_SOCKET = 0xFFFF, Linux SOL_SOCKET = 1 */
    if (level == 0xFFFF) level = SOL_SOCKET;

    /* macOS SO_NOSIGPIPE = 0x1022 — not on Linux, silently ignore */
    if (level == SOL_SOCKET && optname == 0x1022) {
        return 0;
    }

    /* macOS IPPROTO_TCP = 6, IPPROTO_IP = 0, IPPROTO_IPV6 = 41
     * Linux IPPROTO_TCP = 6, IPPROTO_IP = 0, IPPROTO_IPV6 = 41 (same!) */

    /* Translate SOL_SOCKET optnames from macOS to Linux values. */
    if (level == SOL_SOCKET) {
        int translated = translate_sol_socket_optname(optname);
        if (translated != optname && translated > 0) optname = translated;
    }

    static int (*real_setsockopt)(int, int, int, const void *, socklen_t) = NULL;
    if (!real_setsockopt) real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    int ret = real_setsockopt(sockfd, level, optname, optval, optlen);
    int saved_errno = errno;
    /* If setsockopt fails with ENOPROTOOPT or EINVAL, the option doesn't
     * exist on Linux. Silently succeed so curl doesn't abort the connection. */
    if (ret == -1 && (saved_errno == 92 || saved_errno == 22)) {
        return 0;
    }
    if (ret == -1 && macify_caller_is_macos_text(__builtin_return_address(0)))
        errno = macify_linux_to_macos_errno(saved_errno);
    return ret;
}

/* getsockopt — translate macOS SOL_SOCKET level and optname.
 * Critical for curl: after non-blocking connect, curl calls
 * getsockopt(SO_ERROR) to check if the connect succeeded. macOS
 * SO_ERROR=0x1007 must be translated to Linux SO_ERROR=4, otherwise
 * glibc returns ENOPROTOOPT and curl treats connect as failed. */
int macify_getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen) __asm__("getsockopt");
int macify_getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen) {
    if (level == 0xFFFF) level = SOL_SOCKET;
    if (level == SOL_SOCKET) {
        if (optname == 0x1022) {  /* SO_NOSIGPIPE — return 0 (disabled) */
            if (optval && optlen && *optlen >= sizeof(int)) {
                *(int *)optval = 0;
            }
            return 0;
        }
        int translated = translate_sol_socket_optname(optname);
        if (translated != optname) optname = translated;
    }
    static int (*real_getsockopt)(int, int, int, void *, socklen_t *) = NULL;
    if (!real_getsockopt) real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    int ret = real_getsockopt(sockfd, level, optname, optval, optlen);
    if (ret == -1) {
        int saved = errno;
        /* Silently succeed for ENOPROTOOPT (option not supported on Linux) */
        if (saved == 92) return 0;
        if (macify_caller_is_macos_text(__builtin_return_address(0)))
            errno = macify_linux_to_macos_errno(saved);
    }
    return ret;
}

/* connect — translate macOS sockaddr to Linux sockaddr.
 * macOS sockaddr has a 1-byte sa_len at offset 0, then 1-byte sa_family
 * at offset 1. Linux sockaddr has 2-byte sa_family at offset 0 (no sa_len).
 * We must remove the sa_len byte and shift sa_family to offset 0.
 *
 * macOS AF_INET6 = 30, Linux AF_INET6 = 10. */
/* Read /etc/resolv.conf and return the first nameserver IP (static buffer).
 * Used to redirect c-ares's hardcoded 127.0.0.1:53 fallback to the real
 * DNS server. */
static const char *get_resolv_conf_dns_server(void) {
    static char ip[64] = {0};
    if (ip[0]) return ip;
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (!fp) return NULL;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "nameserver", 10) != 0) continue;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        char *end = p;
        while (*end && *end != '\n' && *end != ' ' && *end != '\t') end++;
        *end = '\0';
        if (*p) {
            strncpy(ip, p, sizeof(ip) - 1);
            break;
        }
    }
    fclose(fp);
    return ip[0] ? ip : NULL;
}

int macify_connect(int sockfd, const void *addr, socklen_t addrlen) __asm__("connect");
int macify_connect(int sockfd, const void *addr, socklen_t addrlen) {
    if (!addr || addrlen < 2) { errno = 22; return -1; }
    const uint8_t *p = (const uint8_t *)addr;
    uint8_t linux_addr[256];
    memset(linux_addr, 0, sizeof(linux_addr));
    macify_net_dbg_hex("connect: raw addr:", p, addrlen > 32 ? 32 : addrlen);

    /* Detect macOS sockaddr: either p[0]==16 (sin_len set) or
     * p[1] is a valid macOS family (2=AF_INET, 30=AF_INET6) while
     * p[0] is 0 or not a valid Linux family. */
    int is_macos = 0;
    if (p[0] == 16 && addrlen >= 8) is_macos = 1;       /* sin_len=16 for IPv4 */
    else if (p[0] == 28 && addrlen >= 8) is_macos = 1;   /* sin_len=28 for IPv6 */
    else if (p[0] == 0 && (p[1] == 2 || p[1] == 30) && addrlen >= 8) is_macos = 1; /* sin_len not set */
    /* Also check if p[0] is NOT a valid Linux family but p[1] is a valid macOS family */
    else if (p[0] != 1 && p[0] != 2 && p[0] != 10 && p[0] != 16 && p[0] != 17 &&
             p[1] >= 1 && p[1] <= 30 && addrlen >= 8) is_macos = 1;

    if (is_macos) {
        uint16_t family = p[1];
        if (family == MACOS_AF_INET6) {
            /* IPv6: macOS sockaddr_in6 (28 bytes) → Linux sockaddr_in6 (28 bytes)
             * macOS: [sa_len(1)] [sa_family(1)] [port(2)] [flowinfo(4)] [addr(16)] [scope(4)]
             * Linux: [family(2)] [port(2)] [flowinfo(4)] [addr(16)] [scope(4)] */
            uint16_t lf = LINUX_AF_INET6;
            memcpy(linux_addr + 0, &lf, 2);
            memcpy(linux_addr + 2, p + 2, 2);      /* port */
            memcpy(linux_addr + 4, p + 4, 4);      /* flowinfo */
            memcpy(linux_addr + 8, p + 8, 16);     /* addr (16 bytes!) */
            memcpy(linux_addr + 24, p + 24, 4);    /* scope_id */
            addrlen = 28;
        } else {
            /* IPv4: macOS sockaddr_in (16 bytes) → Linux sockaddr_in (16 bytes) */
            uint16_t lf = 2; /* AF_INET */
            memcpy(linux_addr + 0, &lf, 2);
            memcpy(linux_addr + 2, p + 2, 2);      /* port */
            memcpy(linux_addr + 4, p + 4, 4);      /* addr */
            addrlen = 16;
        }

        /* Redirect 127.0.0.1:53 (c-ares's hardcoded fallback) to the real
         * DNS server from /etc/resolv.conf. c-ares on macOS uses
         * dns_configuration_copy/SCDynamicStore to get DNS servers, but
         * our stubs return NULL, so c-ares falls back to 127.0.0.1:53.
         * We redirect those connects to the real DNS server. */
        if (family == 2 /* AF_INET */ &&
            linux_addr[2] == 0x00 && linux_addr[3] == 0x35 /* port 53 */ &&
            linux_addr[4] == 0x7f && linux_addr[5] == 0x00 &&
            linux_addr[6] == 0x00 && linux_addr[7] == 0x01 /* 127.0.0.1 */) {
            const char *real_dns = get_resolv_conf_dns_server();
            if (real_dns) {
                struct in_addr ia;
                if (inet_pton(AF_INET, real_dns, &ia) == 1) {
                    memcpy(linux_addr + 4, &ia.s_addr, 4);
                    char b[128];
                    snprintf(b, sizeof(b), "connect: redirected 127.0.0.1:53 -> %s:53\n", real_dns);
                    macify_net_dbg(b);
                }
            }
        }
    } else {
        /* Already Linux format */
        size_t cl = addrlen; if (cl > sizeof(linux_addr)) cl = sizeof(linux_addr);
        memcpy(linux_addr, p, cl);
    }

    macify_net_dbg_hex("connect: linux addr:", linux_addr, addrlen > 32 ? 32 : addrlen);
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");
    int r = real_connect(sockfd, (const struct sockaddr *)linux_addr, addrlen);
    int saved_errno = errno;
    char buf[128];
    snprintf(buf, sizeof(buf), "connect: ret=%d errno=%d (EINPROGRESS=36 macOS, 115 Linux)\n", r, saved_errno);
    macify_net_dbg(buf);
    /* Only translate errno on failure; do NOT clobber errno on success
     * (callers may check errno even when ret==0, and a stale non-zero
     * errno could be misinterpreted as a failure). Only translate when
     * the caller is the macOS binary itself (Linux libraries like
     * libgnutls expect Linux errno values). */
    if (r == -1 && macify_caller_is_macos_text(__builtin_return_address(0))) {
        errno = macify_linux_to_macos_errno(saved_errno);
    }
    return r;
}

/* bind — translate macOS sockaddr to Linux */
int macify_bind(int sockfd, const void *addr, socklen_t addrlen) __asm__("bind");
int macify_bind(int sockfd, const void *addr, socklen_t addrlen) {
    if (!addr || addrlen < 2) { errno = 22; return -1; }
    const uint8_t *p = (const uint8_t *)addr;
    uint8_t linux_addr[256];
    memset(linux_addr, 0, sizeof(linux_addr));
    if (p[1] == MACOS_AF_INET6 && (p[0] == 28 || p[0] == 0) && addrlen >= 28) {
        uint16_t lf = LINUX_AF_INET6;
        memcpy(linux_addr + 0, &lf, 2);
        memcpy(linux_addr + 2, p + 2, 2);      /* port */
        memcpy(linux_addr + 4, p + 4, 4);      /* flowinfo */
        memcpy(linux_addr + 8, p + 8, 16);     /* addr */
        memcpy(linux_addr + 24, p + 24, 4);    /* scope_id */
        addrlen = 28;
    } else if ((p[0] == 16 || p[0] == 0) && p[1] == 2 && addrlen >= 8) {
        uint16_t lf = 2;
        memcpy(linux_addr + 0, &lf, 2);
        memcpy(linux_addr + 2, p + 2, 2);
        memcpy(linux_addr + 4, p + 4, 4);
        addrlen = 16;
    } else {
        size_t cl = addrlen; if (cl > sizeof(linux_addr)) cl = sizeof(linux_addr);
        memcpy(linux_addr, p, cl);
    }
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_bind) real_bind = dlsym(RTLD_NEXT, "bind");
    return real_bind(sockfd, (const struct sockaddr *)linux_addr, addrlen);
}

/* sendto — translate macOS sockaddr to Linux */
ssize_t macify_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const void *dest_addr, socklen_t addrlen) __asm__("sendto");
ssize_t macify_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const void *dest_addr, socklen_t addrlen) {
    macify_net_dbg("sendto: entered\n");
    flags |= MSG_NOSIGNAL;
    uint8_t linux_addr[256];
    const struct sockaddr *p_addr = NULL;
    socklen_t linux_addrlen = 0;
    if (dest_addr && addrlen >= 2) {
        const uint8_t *p = (const uint8_t *)dest_addr;
        memset(linux_addr, 0, sizeof(linux_addr));
        if (p[1] == MACOS_AF_INET6 && (p[0] == 28 || p[0] == 0) && addrlen >= 28) {
            uint16_t lf = LINUX_AF_INET6;
            memcpy(linux_addr + 0, &lf, 2);
            memcpy(linux_addr + 2, p + 2, 2);
            memcpy(linux_addr + 4, p + 4, 4);
            memcpy(linux_addr + 8, p + 8, 16);
            memcpy(linux_addr + 24, p + 24, 4);
            linux_addrlen = 28;
        } else if ((p[0] == 16 || p[0] == 0) && p[1] == 2 && addrlen >= 8) {
            uint16_t lf = 2;
            memcpy(linux_addr + 0, &lf, 2);
            memcpy(linux_addr + 2, p + 2, 2);
            memcpy(linux_addr + 4, p + 4, 4);
            linux_addrlen = 16;
        } else {
            size_t cl = addrlen; if (cl > sizeof(linux_addr)) cl = sizeof(linux_addr);
            memcpy(linux_addr, p, cl);
            linux_addrlen = cl;
        }
        p_addr = (const struct sockaddr *)linux_addr;
    }
    static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    ssize_t r = real_sendto(sockfd, buf, len, flags, p_addr, linux_addrlen);
    int saved = errno;
    {
        char b[200];
        snprintf(b, sizeof(b), "sendto: fd=%d len=%zu flags=0x%x dest=%p ret=%zd errno=%d\n",
                 sockfd, len, flags, dest_addr, r, saved);
        macify_net_dbg(b);
    }
    TRANSLATE_ERRNO(r);
        errno = macify_linux_to_macos_errno(saved);
    return r;
}

/* send — add MSG_NOSIGNAL (macOS uses SO_NOSIGPIPE instead) */
ssize_t macify_send(int sockfd, const void *buf, size_t len, int flags) __asm__("send");
ssize_t macify_send(int sockfd, const void *buf, size_t len, int flags) {
    macify_net_dbg("send: entered\n");
    flags |= MSG_NOSIGNAL;  /* prevent SIGPIPE since SO_NOSIGPIPE is no-op */
    static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");
    ssize_t r = real_send(sockfd, buf, len, flags);
    int saved = errno;
    {
        char b[160];
        snprintf(b, sizeof(b), "send: fd=%d len=%zu flags=0x%x ret=%zd errno=%d\n",
                 sockfd, len, flags, r, saved);
        macify_net_dbg(b);
    }
    TRANSLATE_ERRNO(r);
        errno = macify_linux_to_macos_errno(saved);
    return r;
}

/* recv — delegate to glibc (same API).
 * Only translate errno when the caller is the macOS binary itself; Linux
 * libraries (e.g. libgnutls) call recv through our shim too and must see
 * Linux errno values (especially EAGAIN=11). */
ssize_t macify_recv(int sockfd, void *buf, size_t len, int flags) __asm__("recv");
ssize_t macify_recv(int sockfd, void *buf, size_t len, int flags) {
    static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
    if (!real_recv) real_recv = dlsym(RTLD_NEXT, "recv");
    ssize_t r = real_recv(sockfd, buf, len, flags);
    int saved = errno;
    {
        char b[160];
        snprintf(b, sizeof(b), "recv: fd=%d len=%zu flags=0x%x ret=%zd errno=%d\n",
                 sockfd, len, flags, r, saved);
        macify_net_dbg(b);
    }
    TRANSLATE_ERRNO(r);
        errno = macify_linux_to_macos_errno(saved);
    return r;
}

/* Forward declaration — defined after accept/getsockname section */
void linux_to_macos_sockaddr(void *addr, socklen_t addrlen);

/* recvfrom — convert Linux sockaddr to macOS format */
ssize_t macify_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        void *src_addr, socklen_t *addrlen) __asm__("recvfrom");
ssize_t macify_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        void *src_addr, socklen_t *addrlen) {
    static ssize_t (*real_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    ssize_t ret = real_recvfrom(sockfd, buf, len, flags, (struct sockaddr *)src_addr, addrlen);
    if (ret == -1) {
        if (macify_caller_is_macos_text(__builtin_return_address(0))) {
            int saved = errno;
            errno = macify_linux_to_macos_errno(saved);
        }
    } else if (src_addr && addrlen && *addrlen >= 2) {
        linux_to_macos_sockaddr(src_addr, *addrlen);
    }
    return ret;
}

/* sendmsg — pass through to glibc but translate errno. macOS curl's c-ares
 * uses sendmsg to send UDP DNS queries. */
ssize_t macify_sendmsg(int sockfd, const void *msg, int flags) __asm__("sendmsg");
ssize_t macify_sendmsg(int sockfd, const void *msg, int flags) {
    macify_net_dbg("sendmsg: entered\n");
    static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
    if (!real_sendmsg) real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    ssize_t r = real_sendmsg(sockfd, (const struct msghdr *)msg, flags);
    int saved = errno;
    {
        char b[160];
        snprintf(b, sizeof(b), "sendmsg: fd=%d flags=0x%x ret=%zd errno=%d\n",
                 sockfd, flags, r, saved);
        macify_net_dbg(b);
    }
    TRANSLATE_ERRNO(r);
        errno = macify_linux_to_macos_errno(saved);
    return r;
}

/* recvmsg — pass through to glibc but translate errno and AF_INET6. */
ssize_t macify_recvmsg(int sockfd, void *msg, int flags) __asm__("recvmsg");
ssize_t macify_recvmsg(int sockfd, void *msg, int flags) {
    static ssize_t (*real_recvmsg)(int, struct msghdr *, int) = NULL;
    if (!real_recvmsg) real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    ssize_t r = real_recvmsg(sockfd, (struct msghdr *)msg, flags);
    int saved = errno;
    {
        char b[160];
        snprintf(b, sizeof(b), "recvmsg: fd=%d flags=0x%x ret=%zd errno=%d\n",
                 sockfd, flags, r, saved);
        macify_net_dbg(b);
    }
    TRANSLATE_ERRNO(r);
        errno = macify_linux_to_macos_errno(saved);
    return r;
}

/* accept — convert Linux sockaddr to macOS format */
int macify_accept(int sockfd, void *addr, socklen_t *addrlen) __asm__("accept");
int macify_accept(int sockfd, void *addr, socklen_t *addrlen) {
    static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
    if (!real_accept) real_accept = dlsym(RTLD_NEXT, "accept");
    int ret = real_accept(sockfd, (struct sockaddr *)addr, addrlen);
    if (ret >= 0 && addr && addrlen && *addrlen >= 2) {
        linux_to_macos_sockaddr(addr, *addrlen);
    }
    return ret;
}

/* getsockname / getpeername — convert Linux sockaddr to macOS format.
 * Linux sockaddr: [sa_family(2)] [data(14)]
 * macOS sockaddr:  [sa_len(1)] [sa_family(1)] [data(14)]
 * curl reads sa_family from offset 1 (macOS layout), so we must shift. */
void linux_to_macos_sockaddr(void *addr, socklen_t addrlen) {
    if (!addr || addrlen < 2) return;
    uint8_t *p = (uint8_t *)addr;
    uint8_t linux_family = p[0];  /* Linux: family is at offset 0 (low byte) */
    uint8_t macos_family = linux_family;
    if (linux_family == LINUX_AF_INET6) macos_family = MACOS_AF_INET6;
    /* Shift: move bytes 1..N right by 1, put sa_len at 0, sa_family at 1 */
    memmove(p + 1, p, addrlen - 1);
    p[0] = (uint8_t)addrlen;  /* sa_len */
    p[1] = macos_family;     /* sa_family */
}

int macify_getsockname(int sockfd, void *addr, socklen_t *addrlen) __asm__("getsockname");
int macify_getsockname(int sockfd, void *addr, socklen_t *addrlen) {
    static int (*real)(int, struct sockaddr *, socklen_t *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getsockname");
    
    int ret = real(sockfd, (struct sockaddr *)addr, addrlen);
    if (ret >= 0 && addr && addrlen && *addrlen >= 2) {
        linux_to_macos_sockaddr(addr, *addrlen);
    }
    return ret;
}

int macify_getpeername(int sockfd, void *addr, socklen_t *addrlen) __asm__("getpeername");
int macify_getpeername(int sockfd, void *addr, socklen_t *addrlen) {
    static int (*real)(int, struct sockaddr *, socklen_t *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getpeername");
    int ret = real(sockfd, (struct sockaddr *)addr, addrlen);
    if (ret >= 0 && addr && addrlen && *addrlen >= 2) {
        linux_to_macos_sockaddr(addr, *addrlen);
    }
    return ret;
}

/* socket — translate macOS address family constants to Linux.
 * macOS AF_INET6 = 30, Linux AF_INET6 = 10. Other families are the same.
 * macOS SOL_SOCKET = 0xFFFF, Linux SOL_SOCKET = 1 (handled in setsockopt). */

int macify_socket(int domain, int type, int protocol) __asm__("socket");
int macify_socket(int domain, int type, int protocol) {
    char buf[128];
    snprintf(buf, sizeof(buf), "socket: domain=%d type=%d proto=%d\n", domain, type, protocol);
    macify_net_dbg(buf);
    if (domain == MACOS_AF_INET6) domain = LINUX_AF_INET6;
    /* On Linux, socket(AF_INET, SOCK_STREAM, 0) is preferred over
     * specifying IPPROTO_TCP (6) explicitly. Some macOS binaries pass 6. */
    if (protocol == 6) protocol = 0;  /* IPPROTO_TCP → default */
    static int (*real_socket)(int, int, int) = NULL;
    if (!real_socket) real_socket = dlsym(RTLD_NEXT, "socket");
    int r = real_socket(domain, type, protocol);
    if (r == -1 && macify_caller_is_macos_text(__builtin_return_address(0))) {
        int saved = errno;
        errno = macify_linux_to_macos_errno(saved);
    }
    snprintf(buf, sizeof(buf), "socket: ret=%d errno=%d\n", r, errno);
    macify_net_dbg(buf);
    return r;
}

/* inet_ntop — macOS AF_INET6 = 30, Linux AF_INET6 = 10. The macOS binary
 * passes AF_INET6=30 to inet_ntop, which Linux doesn't understand. */
const char *macify_inet_ntop(int af, const void *src, char *dst, socklen_t size) __asm__("inet_ntop");
const char *macify_inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    if (macify_net_debug_enabled < 0) {
        const char *e = getenv("MACIFY_NET_DEBUG");
        macify_net_debug_enabled = (e && e[0]) ? 1 : 0;
    }
    if (macify_net_debug_enabled) {
        char b[128];
        snprintf(b, sizeof(b), "inet_ntop: af=%d src=%p\n", af, src);
        (void)write(2, b, strlen(b));
    }
    /* Translate macOS address family constants to Linux */
    if (af == MACOS_AF_INET6) af = LINUX_AF_INET6;
    /* Also handle macOS sa_len being passed as AF (16 for IPv4, 28 for IPv6) */
    if (af == 16) af = 2;       /* sa_len=16 → AF_INET */
    else if (af == 28) af = 10; /* sa_len=28 → AF_INET6 (Linux) */
    static const char *(*real)(int, const void *, char *, socklen_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "inet_ntop");
    const char *result = real(af, src, dst, size);
    if (macify_net_debug_enabled) {
        char b[128];
        snprintf(b, sizeof(b), "inet_ntop: result=%p dst=%s errno=%d\n",
                 (void *)result, result ? dst : "(null)", errno);
        (void)write(2, b, strlen(b));
    }
    return result;
}

/* inet_pton — translate AF_INET6 */
int macify_inet_pton(int af, const char *src, void *dst) __asm__("inet_pton");
int macify_inet_pton(int af, const char *src, void *dst) {
    if (af == MACOS_AF_INET6) af = LINUX_AF_INET6;
    static int (*real)(int, const char *, void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "inet_pton");
    return real(af, src, dst);
}
