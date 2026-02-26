// Licensed under the Apache-2.0 license

/**
 * Minimal stdlib.h stub for lwIP bare-metal builds.
 *
 * Only declares the functions lwIP actually calls.
 * Implementation is in libc_stubs.c.
 */

#ifndef _STDLIB_H
#define _STDLIB_H

int atoi(const char *nptr);

#endif /* _STDLIB_H */
