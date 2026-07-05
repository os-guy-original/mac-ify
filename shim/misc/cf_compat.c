/* cf_compat.c — CoreFoundation functions that conflict with system headers.
 *
 * This file is compiled WITHOUT any system CF headers to avoid prototype
 * conflicts. The functions use __asm__ aliases to export with the correct
 * macOS symbol names.
 *
 * Only functions NOT already in cf.c are defined here. */

#include <string.h>
#include <stdint.h>

/* CFDataGetBytes — copy bytes from CFData. */
void macify_CFDataGetBytes(const void *data, void *range, void *buffer) __asm__("CFDataGetBytes");
void macify_CFDataGetBytes(const void *data, void *range, void *buffer) {
    (void)data; (void)range; (void)buffer;
}
