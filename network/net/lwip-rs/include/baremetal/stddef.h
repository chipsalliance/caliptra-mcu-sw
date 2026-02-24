// Licensed under the Apache-2.0 license

/**
 * Minimal stddef.h for lwIP bare-metal builds (riscv32 ILP32).
 *
 * Provides size_t, ptrdiff_t, and NULL without depending on any C library.
 */

#ifndef _STDDEF_H
#define _STDDEF_H

typedef unsigned int size_t;
typedef int          ptrdiff_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

/* offsetof macro */
#define offsetof(type, member) __builtin_offsetof(type, member)

#endif /* _STDDEF_H */
