// Licensed under the Apache-2.0 license

/**
 * Minimal string.h stub for lwIP bare-metal builds.
 *
 * Only declares the functions lwIP actually calls.
 * Implementations are provided by compiler_builtins (memcpy, memset, memmove,
 * memcmp) and libc_stubs.c (strlen, strcmp, strncmp, strstr).
 */

#ifndef _STRING_H
#define _STRING_H

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int   memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
int   strcmp(const char *s1, const char *s2);
int   strncmp(const char *s1, const char *s2, size_t n);
char *strstr(const char *haystack, const char *needle);

#endif /* _STRING_H */
