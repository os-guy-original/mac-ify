/* libintl.c — libintl (gettext) shim — additional functions
 *
 * macOS binaries from MacPorts/Homebrew link against libintl.8.dylib.
 * On Linux, glibc provides gettext functions WITHOUT the libintl_ prefix.
 *
 * NOTE: libintl_gettext, libintl_dgettext, libintl_ngettext,
 * libintl_bindtextdomain, libintl_textdomain, and libintl_setlocale
 * are already defined in shim/sys/misc_stubs.c. This file provides
 * the REMAINING functions that macOS binaries import:
 *   - libintl_dcgettext
 *   - libintl_dcngettext
 *   - libintl_dngettext
 *   - libintl_bind_textdomain_codeset
 *
 * Without these, macOS binaries like awk (from MacPorts) crash because
 * the GOT entries resolve to 0 (NULL). */

#include "io_internal.h"
#include <locale.h>

char *macify_libintl_dcgettext(const char *domainname, const char *msgid, int category) __asm__("libintl_dcgettext");
char *macify_libintl_dcgettext(const char *domainname, const char *msgid, int category) {
    (void)category;
    static char *(*real_dgettext)(const char *, const char *) = NULL;
    if (!real_dgettext) real_dgettext = dlsym(RTLD_DEFAULT, "dgettext");
    if (real_dgettext && domainname && msgid) return real_dgettext(domainname, msgid);
    return (char *)msgid;
}

char *macify_libintl_dngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long n) __asm__("libintl_dngettext");
char *macify_libintl_dngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long n) {
    static char *(*real_dngettext)(const char *, const char *, const char *, unsigned long) = NULL;
    if (!real_dngettext) real_dngettext = dlsym(RTLD_DEFAULT, "dngettext");
    if (real_dngettext && domainname && msgid1 && msgid2) return real_dngettext(domainname, msgid1, msgid2, n);
    return (char *)(n == 1 ? msgid1 : msgid2);
}

char *macify_libintl_dcngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long n, int category) __asm__("libintl_dcngettext");
char *macify_libintl_dcngettext(const char *domainname, const char *msgid1, const char *msgid2, unsigned long n, int category) {
    (void)category;
    static char *(*real_dngettext)(const char *, const char *, const char *, unsigned long) = NULL;
    if (!real_dngettext) real_dngettext = dlsym(RTLD_DEFAULT, "dngettext");
    if (real_dngettext && domainname && msgid1 && msgid2) return real_dngettext(domainname, msgid1, msgid2, n);
    return (char *)(n == 1 ? msgid1 : msgid2);
}

char *macify_libintl_bind_textdomain_codeset(const char *domainname, const char *codeset) __asm__("libintl_bind_textdomain_codeset");
char *macify_libintl_bind_textdomain_codeset(const char *domainname, const char *codeset) {
    static char *(*real)(const char *, const char *) = NULL;
    if (!real) real = dlsym(RTLD_DEFAULT, "bind_textdomain_codeset");
    if (real && domainname) return real(domainname, codeset);
    return (char *)codeset;
}
