/* rune.c — macOS _DefaultRuneLocale and character classification */
#include "../shim.h"
#include <ctype.h>

/* _DefaultRuneLocale — macOS rune/cType table.
 * 
 * macOS uses a rune table for character classification (isalpha, etc).
 * The _DefaultRuneLocale global is a struct _RuneLocale that contains
 * the default C locale character table. On Linux, character classification
 * uses a different mechanism (locale.h).
 * 
 * We provide a zeroed-out table. This means isalpha() etc. won't work
 * correctly, but the binary can at least load and run. For proper
 * classification support, we'd need to populate the table fields.
 */

#include <ctype.h>

/* macOS _RuneLocale structure.
 *
 * On macOS, the runetype/maplower/mapupper arrays are INLINE in the struct,
 * not pointers. tree reads _DefaultRuneLocale.__runetype[c] directly.
 *
 * Actual macOS layout (from <runetype.h>):
 *   char magic[8]          offset 0
 *   uint32_t encoding      offset 8
 *   void *sgetrune         offset 16 (pointer, 8 bytes on 64-bit)
 *   void *sputrune         offset 24
 *   uint32_t invalid_rune  offset 32
 *   uint32_t __pad         offset 36 (alignment for pointer)
 *   void *runes            offset 40
 *   uint32_t nrunes        offset 48
 *   uint32_t __pad2        offset 52
 *   char variablehigh[...]
 *   ... then __runetype[256], __maplower[256], __mapupper[256]
 *
 * But the actual access pattern depends on the macOS version. The simplest
 * fix: make the struct large enough and put the runetype data at the right
 * offset. We use a flat byte array and populate it. */

/* The macOS _RuneLocale has __runetype as an inline array of uint32_t[256]
 * at a known offset. tree accesses it as:
 *   _DefaultRuneLocale.__runetype[(unsigned char)c] & mask
 *
 * We provide a flat layout that matches what tree expects. */
struct _macify_RuneLocale {
    char magic[8];              /* 0: "RuneMag1" */
    uint32_t encoding;          /* 8 */
    void *sgetrune;             /* 16 */
    void *sputrune;             /* 24 */
    uint32_t invalid_rune;      /* 32 */
    uint32_t _pad1;             /* 36 */
    void *runes;                /* 40 */
    uint32_t nrunes;            /* 48 */
    uint32_t _pad2;             /* 52 */
    /* macOS _RuneLocale has __runetype at offset 0x3c (60).
     * Confirmed by disassembling CONF_parse_list which accesses
     * [rcx + char*4 + 0x3c] where rcx = _DefaultRuneLocale.
     * The 4 bytes between _pad2 (52) and __runetype (60) are
     * likely __variablehigh or another field. */
    uint32_t _pad3;             /* 56 */
    uint32_t __runetype[256];   /* 60: inline runetype table */
    int16_t  __maplower[256];   /* inline lower case map */
    int16_t  __mapupper[256];   /* inline upper case map */
};

/* Provide a static _DefaultRuneLocale that's big enough to not crash.
 * The macOS binary reads from _DefaultRuneLocale to do character classification.
 * We'll populate the runetype table with basic ASCII classification. */
uint32_t macify_runetype[256];
int16_t macify_maplower[256];
int16_t macify_mapupper[256];

struct _macify_RuneLocale _DefaultRuneLocale = {
    .magic = {'R','u','n','e','M','a','g','1'},
    .encoding = 0,
    .sgetrune = NULL,
    .sputrune = NULL,
    .invalid_rune = 0xFFFD,
    ._pad1 = 0,
    .runes = NULL,
    .nrunes = 256,
    ._pad2 = 0,
};

__attribute__((constructor))
static void macify_init_rune(void) {
    /* Populate basic ASCII character tables — both the standalone arrays
     * (used by __maskrune) and the inline arrays in _DefaultRuneLocale
     * (read directly by some binaries like tree).
     *
     * macOS _CTYPE flag values (from <runetype.h>):
     *   _CTYPE_A = 0x00000100  alpha
     *   _CTYPE_C = 0x00000200  ctrl
     *   _CTYPE_D = 0x00000400  digit
     *   _CTYPE_G = 0x00000800  graph
     *   _CTYPE_L = 0x00001000  lower
     *   _CTYPE_P = 0x00002000  punct
     *   _CTYPE_S = 0x00004000  space
     *   _CTYPE_U = 0x00008000  upper
     *   _CTYPE_X = 0x00010000  xdigit
     *   _CTYPE_B = 0x00020000  blank
     *   _CTYPE_R = 0x00040000  print
     *   _CTYPE_I = 0x00080000  ideogram
     *   _CTYPE_T = 0x00100000  special
     *   _CTYPE_Q = 0x00200000  phonogram
     *   _CTYPE_SW0= 0x20000000  sw0
     *   _CTYPE_SW1= 0x40000000  sw1
     *   _CTYPE_SW2= 0x80000000  sw2
     */
    for (int c = 0; c < 256; c++) {
        uint32_t flags = 0;
        if (isalpha(c))  flags |= 0x00000100;  /* _CTYPE_A */
        if (iscntrl(c))  flags |= 0x00000200;  /* _CTYPE_C */
        if (isdigit(c))  flags |= 0x00000400;  /* _CTYPE_D */
        if (isgraph(c))  flags |= 0x00000800;  /* _CTYPE_G */
        if (islower(c))  flags |= 0x00001000;  /* _CTYPE_L */
        if (ispunct(c))  flags |= 0x00002000;  /* _CTYPE_P */
        if (isspace(c))  flags |= 0x00004000;  /* _CTYPE_S */
        if (isupper(c))  flags |= 0x00008000;  /* _CTYPE_U */
        if (isxdigit(c)) flags |= 0x00010000;  /* _CTYPE_X */
        if (isblank(c))  flags |= 0x00020000;  /* _CTYPE_B */
        if (isprint(c))  flags |= 0x00040000;  /* _CTYPE_R */
        macify_runetype[c] = flags;
        macify_maplower[c] = tolower(c);
        macify_mapupper[c] = toupper(c);
        /* Also populate inline arrays in _DefaultRuneLocale */
        _DefaultRuneLocale.__runetype[c] = flags;
        _DefaultRuneLocale.__maplower[c] = tolower(c);
        _DefaultRuneLocale.__mapupper[c] = toupper(c);
    }
}

/* __maskrune — macOS character classification.
 * 
 * Returns the runetype flags for character `ch` ANDed with `mask`.
 * Used by isalpha(), isdigit(), etc. on macOS.
 */
unsigned long __maskrune(unsigned long ch, unsigned long mask) {
    if (ch < 256) {
        return macify_runetype[ch] & mask;
    }
    return 0;
}

/* __isctype — another macOS classification helper */
#undef __isctype
int __isctype(int ch, unsigned long mask) {
    if (ch < 256) {
        return (macify_runetype[ch] & mask) != 0;
    }
    return 0;
}

/* __toupper / __tolower — macOS internal versions */
int __toupper(int ch) { return toupper(ch); }
int __tolower(int ch) { return tolower(ch); }

