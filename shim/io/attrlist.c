/* attrlist.c — getattrlist/fgetattrlist/setattrlist/fsetattrlist.
 *
 * General fix (T0007): these macOS attribute-list APIs were stubs that
 * returned ENOTSUP, which made ruby's glob (dir.c replace_real_basename,
 * guarded by HAVE_GETATTRLIST in darwin builds) silently return empty
 * for every pattern with a literal non-root segment (ruby's glob
 * and broke case-sensitivity probes (is_case_sensitive via
 * ATTR_VOL_CAPABILITIES) and the normalization check
 * (need_normalization via ATTR_CMN_OBJTAG) in the same file.
 *
 * ABI ground truth: docs/darwin/getattrlist.2.txt (xnu bsd/man),
 * docs/darwin/attr.h (xnu bsd/sys). Buffer layout: u_int32_t total
 * length (including itself), then attributes packed in attr-bit order
 * (bit 31 first), each aligned to 4 bytes; variable-length attributes
 * are attrreference_t {int32 dataoffset; u32 length} where dataoffset
 * is relative to the attrreference itself. Sizes from attr.h:
 * attribute_set_t = 5xu32, vol_capabilities_set_t = u32[4],
 * fsobj_type_t/tag_t = u32, ATTR_CMN_FILEID/PARENTID = u_int32_t.
 *
 * Supported common attributes: RETURNED_ATTRS, NAME, OBJTYPE, OBJTAG,
 * DEVID, FNDRINFO (zeroed), FILEID, PARENTID, the four timespec64
 * times. Volume: VOL_INFO (ATTR_VOL_INFO), VOL_CAPABILITIES
 * (case-sensitive bit set, everything else marked valid-and-off).
 * Directory: LINKCOUNT, ENTRYCOUNT. File: LINKCOUNT, TOTALSIZE,
 * ALLOCSIZE, IOBLOCKSIZE, DEVTYPE, DATALENGTH. Everything else is
 * reported as not-returned via RETURNED_ATTRS (kernel semantics:
 * unsupported attributes are skipped unless FSOPT_PACK_INVAL_ATTRS).
 *
 * Object types (xnu vnode.h enum vtype): VNON=0, VREG=1, VDIR=2,
 * VBLK=3, VCHR=4, VLNK=5, VSOCK=6, VFIFO=7. Tags (enum vtagtype):
 * VT_NON=0, VT_UFS=1, ..., VT_HFS=16. We report VT_HFS so darwin
 * callers take their HFS-flavored paths consistently. */

#include "../shim.h"
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

extern int macify_translate_path(const char *, char *, size_t);
extern int macify_should_hide_path(const char *);

/* ── attr.h constants (fetched from xnu) ─────────────────────── */

#define MACIFY_ATTR_BIT_MAP_COUNT   5
#define MACIFY_FSOPT_NOFOLLOW       0x00000001

#define MACIFY_ATTR_CMN_NAME           0x00000001u
#define MACIFY_ATTR_CMN_DEVID          0x00000002u
#define MACIFY_ATTR_CMN_FSID           0x00000004u
#define MACIFY_ATTR_CMN_OBJTYPE        0x00000008u
#define MACIFY_ATTR_CMN_OBJTAG         0x00000010u
#define MACIFY_ATTR_CMN_CRTIME         0x00000200u
#define MACIFY_ATTR_CMN_MODTIME        0x00000400u
#define MACIFY_ATTR_CMN_CHGTIME        0x00000800u
#define MACIFY_ATTR_CMN_ACCTIME        0x00001000u
#define MACIFY_ATTR_CMN_FNDRINFO       0x00004000u
#define MACIFY_ATTR_CMN_FILEID         0x02000000u
#define MACIFY_ATTR_CMN_PARENTID       0x04000000u
#define MACIFY_ATTR_CMN_RETURNED_ATTRS 0x80000000u

#define MACIFY_ATTR_VOL_CAPABILITIES 0x00020000u
#define MACIFY_ATTR_VOL_INFO         0x80000000u

#define MACIFY_ATTR_DIR_LINKCOUNT  0x00000001u
#define MACIFY_ATTR_DIR_ENTRYCOUNT 0x00000002u

#define MACIFY_ATTR_FILE_LINKCOUNT   0x00000001u
#define MACIFY_ATTR_FILE_TOTALSIZE   0x00000002u
#define MACIFY_ATTR_FILE_ALLOCSIZE   0x00000004u
#define MACIFY_ATTR_FILE_IOBLOCKSIZE 0x00000008u
#define MACIFY_ATTR_FILE_DEVTYPE     0x00000020u
#define MACIFY_ATTR_FILE_DATALENGTH  0x00000200u

struct macify_attrlist {
    uint16_t bitmapcount;
    uint16_t reserved;
    uint32_t commonattr;
    uint32_t volattr;
    uint32_t dirattr;
    uint32_t fileattr;
    uint32_t forkattr;
};

struct macify_attrreference {
    int32_t  attr_dataoffset;
    uint32_t attr_length;
};

/* xnu vnode.h enum vtype */
enum {
    MACIFY_VNON = 0, MACIFY_VREG, MACIFY_VDIR, MACIFY_VBLK, MACIFY_VCHR,
    MACIFY_VLNK, MACIFY_VSOCK, MACIFY_VFIFO, MACIFY_VBAD, MACIFY_VSTR,
    MACIFY_VCPLX
};
/* xnu vnode.h enum vtagtype: VT_NON=0, VT_UFS=1, ... VT_HFS=16 */
#define MACIFY_VT_HFS 16

#define MACIFY_VOL_CAP_FMT_CASE_SENSITIVE 0x00000100u
#define MACIFY_VOL_CAPABILITIES_FORMAT    0

/* ── underlying libc calls ───────────────────────────────────── */

static int (*real_stat)(const char *, struct stat *);
static int (*real_lstat)(const char *, struct stat *);
static int (*real_fstat)(int, struct stat *);

static void macify_attrlist_resolve(void) {
    if (!real_stat)  real_stat  = (int (*)(const char *, struct stat *))macify_elf_lookup("stat");
    if (!real_lstat) real_lstat = (int (*)(const char *, struct stat *))macify_elf_lookup("lstat");
    if (!real_fstat) real_fstat = (int (*)(int, struct stat *))macify_elf_lookup("fstat");
}

/* ── packing helpers ─────────────────────────────────────────── */

static size_t macify_align4(size_t n) { return (n + 3u) & ~3u; }

static void macify_put_u32(unsigned char *p, uint32_t v) { memcpy(p, &v, 4); }
static void macify_put_u64(unsigned char *p, uint64_t v) { memcpy(p, &v, 8); }

/* Apple struct timespec64 (attr.h stXtime / timespec64): two 64-bit
 * signed fields. glibc's struct stat has 64-bit timespecs on x86-64,
 * so the raw values copy over. */
static void macify_put_ts64(unsigned char *p, int64_t sec, int64_t nsec) {
    macify_put_u64(p, (uint64_t)sec);
    macify_put_u64(p + 8, (uint64_t)nsec);
}

static uint32_t macify_vtype_from_mode(uint32_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG:  return MACIFY_VREG;
        case S_IFDIR:  return MACIFY_VDIR;
        case S_IFBLK:  return MACIFY_VBLK;
        case S_IFCHR:  return MACIFY_VCHR;
        case S_IFLNK:  return MACIFY_VLNK;
        case S_IFSOCK: return MACIFY_VSOCK;
        case S_IFIFO:  return MACIFY_VFIFO;
        default:       return MACIFY_VNON;
    }
}

/* ── core implementation ─────────────────────────────────────── */

struct macify_attr_target {
    int have_path;
    const char *path;   /* translated, host-side */
    int fd;
    int nofollow;
    int invalid;        /* hidden path: behave like ENOENT */
};

/* Fill buf (or, when buf is NULL, just compute the needed size).
 * Returns the total packed size, or -1 with errno on failure. */
static int macify_attrlist_fill(const struct macify_attrlist *al,
                                const struct macify_attr_target *t,
                                unsigned char *B, size_t bufsize) {
    struct stat st;

    macify_attrlist_resolve();

    if (t->invalid) { errno = ENOENT; return -1; }

    if (t->have_path) {
        int ret;
        if (t->nofollow && real_lstat)
            ret = real_lstat(t->path, &st);
        else if (real_stat)
            ret = real_stat(t->path, &st);
        else
            ret = -1;
        if (ret != 0) return -1;
    } else {
        if (!real_fstat || real_fstat(t->fd, &st) != 0) return -1;
    }

    uint32_t c = al->commonattr;
    uint32_t returned = 0;
    size_t off = 4; /* leading length field */
    size_t i;
    uint32_t bit;
    const uint32_t time_bits[4] = {
        MACIFY_ATTR_CMN_CRTIME, MACIFY_ATTR_CMN_MODTIME,
        MACIFY_ATTR_CMN_CHGTIME, MACIFY_ATTR_CMN_ACCTIME
    };

#define NEED(n) do { if (bufsize && (n) > bufsize - off) { errno = ERANGE; return -1; } } while (0)

    if (c & MACIFY_ATTR_CMN_RETURNED_ATTRS) {
        NEED(20);                       /* attribute_set_t = 5 x u32 */
        off += 20;
        returned |= MACIFY_ATTR_CMN_RETURNED_ATTRS;
    }
    if (c & MACIFY_ATTR_CMN_NAME) {
        const char *slash = t->have_path && t->path ? strrchr(t->path, '/') : NULL;
        const char *nm = slash ? slash + 1 : (t->have_path && t->path ? t->path : "");
        size_t nl = strlen(nm);
        if (nl > 255) nl = 255;         /* NAME_MAX per man page */
        NEED(8 + macify_align4(nl + 1));
        if (B) {
            struct macify_attrreference ar;
            ar.attr_dataoffset = 8;     /* data follows the reference */
            ar.attr_length = (uint32_t)(nl + 1);
            memcpy(B + off, &ar, 8);
            memcpy(B + off + 8, nm, nl + 1);
        }
        off += 8 + macify_align4(nl + 1);
        returned |= MACIFY_ATTR_CMN_NAME;
    }
    if (c & MACIFY_ATTR_CMN_DEVID) {
        NEED(8); if (B) macify_put_u64(B + off, (uint64_t)st.st_dev);
        off += 8; returned |= MACIFY_ATTR_CMN_DEVID;
    }
    if (c & MACIFY_ATTR_CMN_FSID) {
        NEED(8); if (B) macify_put_u64(B + off, (uint64_t)st.st_dev);
        off += 8; returned |= MACIFY_ATTR_CMN_FSID;
    }
    if (c & MACIFY_ATTR_CMN_OBJTYPE) {
        NEED(4); if (B) macify_put_u32(B + off, macify_vtype_from_mode(st.st_mode));
        off += 4; returned |= MACIFY_ATTR_CMN_OBJTYPE;
    }
    if (c & MACIFY_ATTR_CMN_OBJTAG) {
        NEED(4); if (B) macify_put_u32(B + off, MACIFY_VT_HFS);
        off += 4; returned |= MACIFY_ATTR_CMN_OBJTAG;
    }
    for (i = 0; i < 4; i++) {
        bit = time_bits[i];
        if (!(c & bit)) continue;
        int64_t sec, nsec;
        switch (bit) {
            case MACIFY_ATTR_CMN_CRTIME:  sec = (int64_t)st.st_ctim.tv_sec; nsec = (int64_t)st.st_ctim.tv_nsec; break;
            case MACIFY_ATTR_CMN_MODTIME: sec = (int64_t)st.st_mtim.tv_sec; nsec = (int64_t)st.st_mtim.tv_nsec; break;
            case MACIFY_ATTR_CMN_CHGTIME: sec = (int64_t)st.st_ctim.tv_sec; nsec = (int64_t)st.st_ctim.tv_nsec; break;
            default:                      sec = (int64_t)st.st_atim.tv_sec; nsec = (int64_t)st.st_atim.tv_nsec; break;
        }
        NEED(16); if (B) macify_put_ts64(B + off, sec, nsec);
        off += 16; returned |= bit;
    }
    if (c & MACIFY_ATTR_CMN_FNDRINFO) {
        NEED(32); if (B) memset(B + off, 0, 32);
        off += 32; returned |= MACIFY_ATTR_CMN_FNDRINFO;
    }
    if (c & MACIFY_ATTR_CMN_FILEID) {
        NEED(4); if (B) macify_put_u32(B + off, (uint32_t)st.st_ino);
        off += 4; returned |= MACIFY_ATTR_CMN_FILEID;
    }
    if (c & MACIFY_ATTR_CMN_PARENTID) {
        NEED(4); if (B) macify_put_u32(B + off, 2);
        off += 4; returned |= MACIFY_ATTR_CMN_PARENTID;
    }
    if (al->volattr & MACIFY_ATTR_VOL_INFO) {
        NEED(4); if (B) macify_put_u32(B + off, 0);
        off += 4; returned |= MACIFY_ATTR_VOL_INFO;
    }
    if (al->volattr & MACIFY_ATTR_VOL_CAPABILITIES) {
        /* vol_capabilities_attr_t { capabilities[4]; valid[4] } = 32B */
        NEED(32);
        if (B) {
            uint32_t caps[4] = {0}, valid[4] = {0};
            caps[MACIFY_VOL_CAPABILITIES_FORMAT] = MACIFY_VOL_CAP_FMT_CASE_SENSITIVE;
            valid[MACIFY_VOL_CAPABILITIES_FORMAT] = MACIFY_VOL_CAP_FMT_CASE_SENSITIVE;
            memcpy(B + off, caps, 16);
            memcpy(B + off + 16, valid, 16);
        }
        off += 32;
        returned |= MACIFY_ATTR_VOL_CAPABILITIES;
    }
    if (al->dirattr & MACIFY_ATTR_DIR_LINKCOUNT) {
        NEED(4);
        if (B) macify_put_u32(B + off, S_ISDIR(st.st_mode) ? 2 : 1);
        off += 4; returned |= MACIFY_ATTR_DIR_LINKCOUNT;
    }
    if (al->dirattr & MACIFY_ATTR_DIR_ENTRYCOUNT) {
        NEED(4); if (B) macify_put_u32(B + off, 0);
        off += 4; returned |= MACIFY_ATTR_DIR_ENTRYCOUNT;
    }
    if (al->fileattr & MACIFY_ATTR_FILE_LINKCOUNT) {
        NEED(4); if (B) macify_put_u32(B + off, (uint32_t)st.st_nlink);
        off += 4; returned |= MACIFY_ATTR_FILE_LINKCOUNT;
    }
    if (al->fileattr & MACIFY_ATTR_FILE_TOTALSIZE) {
        NEED(8); if (B) macify_put_u64(B + off, (uint64_t)st.st_size);
        off += 8; returned |= MACIFY_ATTR_FILE_TOTALSIZE;
    }
    if (al->fileattr & MACIFY_ATTR_FILE_ALLOCSIZE) {
        NEED(8); if (B) macify_put_u64(B + off, (uint64_t)st.st_blocks * 512);
        off += 8; returned |= MACIFY_ATTR_FILE_ALLOCSIZE;
    }
    if (al->fileattr & MACIFY_ATTR_FILE_IOBLOCKSIZE) {
        NEED(4); if (B) macify_put_u32(B + off, (uint32_t)st.st_blksize);
        off += 4; returned |= MACIFY_ATTR_FILE_IOBLOCKSIZE;
    }
    if (al->fileattr & MACIFY_ATTR_FILE_DEVTYPE) {
        NEED(8); if (B) macify_put_u64(B + off, (uint64_t)st.st_rdev);
        off += 8; returned |= MACIFY_ATTR_FILE_DEVTYPE;
    }
    if (al->fileattr & MACIFY_ATTR_FILE_DATALENGTH) {
        NEED(8); if (B) macify_put_u64(B + off, (uint64_t)st.st_size);
        off += 8; returned |= MACIFY_ATTR_FILE_DATALENGTH;
    }

#undef NEED

    if (B) {
        macify_put_u32(B, (uint32_t)off);
        if (c & MACIFY_ATTR_CMN_RETURNED_ATTRS) {
            /* attribute_set_t sits at offset 4 (always first attr) */
            uint32_t as[5] = {0};
            as[0] = returned & ~(MACIFY_ATTR_CMN_RETURNED_ATTRS |
                                 MACIFY_ATTR_VOL_CAPABILITIES | MACIFY_ATTR_VOL_INFO |
                                 MACIFY_ATTR_DIR_LINKCOUNT | MACIFY_ATTR_DIR_ENTRYCOUNT |
                                 MACIFY_ATTR_FILE_LINKCOUNT | MACIFY_ATTR_FILE_TOTALSIZE |
                                 MACIFY_ATTR_FILE_ALLOCSIZE | MACIFY_ATTR_FILE_IOBLOCKSIZE |
                                 MACIFY_ATTR_FILE_DEVTYPE | MACIFY_ATTR_FILE_DATALENGTH);
            as[1] = returned & (MACIFY_ATTR_VOL_CAPABILITIES | MACIFY_ATTR_VOL_INFO);
            as[2] = returned & (MACIFY_ATTR_DIR_LINKCOUNT | MACIFY_ATTR_DIR_ENTRYCOUNT);
            as[3] = returned & (MACIFY_ATTR_FILE_LINKCOUNT | MACIFY_ATTR_FILE_TOTALSIZE |
                                MACIFY_ATTR_FILE_ALLOCSIZE | MACIFY_ATTR_FILE_IOBLOCKSIZE |
                                MACIFY_ATTR_FILE_DEVTYPE | MACIFY_ATTR_FILE_DATALENGTH);
            /* as[4] forkattr = 0 */
            memcpy(B + 4, as, 20);
        }
    }
    return (int)off;
}

static int macify_attrlist_common(const struct macify_attrlist *al,
                                  const struct macify_attr_target *t,
                                  void *attrBuf, size_t attrBufSize) {
    if (!al || al->bitmapcount != MACIFY_ATTR_BIT_MAP_COUNT) { errno = EINVAL; return -1; }
    /* Volume attributes require ATTR_VOL_INFO per the man page */
    if (al->volattr & ~MACIFY_ATTR_VOL_INFO &&
        !(al->volattr & MACIFY_ATTR_VOL_INFO)) { errno = EINVAL; return -1; }

    if (t->have_path && t->path && macify_should_hide_path(t->path)) {
        errno = ENOENT;
        return -1;
    }

    int r;
    if (!attrBuf) {
        /* size query: caller wants the needed length */
        r = macify_attrlist_fill(al, t, NULL, 0);
    } else {
        if (attrBufSize < 4) { errno = EINVAL; return -1; }
        r = macify_attrlist_fill(al, t, (unsigned char *)attrBuf, attrBufSize);
        if (r >= 0) errno = 0;
    }
    /* getattrlist ABI: 0 on success, -1 on error (not the byte count;
     * the total length is the first field of attrBuf itself). */
    return r < 0 ? -1 : 0;
}

/* ── exported entry points ───────────────────────────────────── */

int macify_getattrlist(const char *path, void *alist, void *attrBuf,
                       size_t attrBufSize, unsigned long options) __asm__("getattrlist");
int macify_getattrlist(const char *path, void *alist, void *attrBuf,
                       size_t attrBufSize, unsigned long options) {
    int is_macos = macify_caller_is_macos_text(__builtin_return_address(0));
    if (getenv("MACIFY_TRACE_OPEN")) {
        char b[256]; int n = snprintf(b, sizeof(b),
            "macify: getattrlist(\"%s\", bufsize=%zu, opts=0x%lx) macos_caller=%d\n",
            path ? path : "(null)", attrBufSize, options, is_macos);
        (void)write(2, b, n);
    }
    if (!is_macos)
        return -1;

    struct macify_attr_target t;
    memset(&t, 0, sizeof(t));
    t.have_path = 1;
    t.nofollow = (options & MACIFY_FSOPT_NOFOLLOW) != 0;

    const char *eff = path;
    char tp[4096];
    if (path && macify_translate_path(path, tp, sizeof(tp)) == 0) eff = tp;
    t.path = eff;

    return macify_attrlist_common((const struct macify_attrlist *)alist, &t,
                                  attrBuf, attrBufSize);
}

int macify_fgetattrlist(int fd, void *alist, void *attrBuf,
                        size_t attrBufSize, unsigned long options) __asm__("fgetattrlist");
int macify_fgetattrlist(int fd, void *alist, void *attrBuf,
                        size_t attrBufSize, unsigned long options) {
    if (!macify_caller_is_macos_text(__builtin_return_address(0)))
        return -1;

    struct macify_attr_target t;
    memset(&t, 0, sizeof(t));
    t.fd = fd;

    return macify_attrlist_common((const struct macify_attrlist *)alist, &t,
                                  attrBuf, attrBufSize);
}

int macify_setattrlist(const char *path, void *alist, void *attrBuf,
                       size_t attrBufSize, unsigned long options) __asm__("setattrlist");
int macify_setattrlist(const char *path, void *alist, void *attrBuf,
                       size_t attrBufSize, unsigned long options) {
    (void)path; (void)alist; (void)attrBuf; (void)attrBufSize; (void)options;
    errno = ENOSYS;
    return -1;
}

int macify_fsetattrlist(int fd, void *alist, void *attrBuf,
                        size_t attrBufSize, unsigned long options) __asm__("fsetattrlist");
int macify_fsetattrlist(int fd, void *alist, void *attrBuf,
                        size_t attrBufSize, unsigned long options) {
    (void)fd; (void)alist; (void)attrBuf; (void)attrBufSize; (void)options;
    errno = ENOSYS;
    return -1;
}
