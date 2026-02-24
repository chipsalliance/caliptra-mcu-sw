// Licensed under the Apache-2.0 license

/**
 * Minimal stdio.h stub for lwIP bare-metal builds.
 *
 * lwIP's mem.c includes stdio.h for snprintf, but only uses it under
 * MEM_OVERFLOW_CHECK which is disabled in our baremetal config.
 */

#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>
#include <stdarg.h>

int snprintf(char *str, size_t size, const char *format, ...);

#endif /* _STDIO_H */
