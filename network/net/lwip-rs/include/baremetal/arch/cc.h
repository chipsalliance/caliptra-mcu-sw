// Licensed under the Apache-2.0 license

/**
 * @file cc.h
 * Bare-metal RISC-V compiler/platform abstraction for lwIP
 *
 * Configures lwIP to not use system headers that aren't available
 * in a freestanding environment (no libc).
 */

#ifndef __ARCH_CC_H__
#define __ARCH_CC_H__

#include <stdint.h>
#include <stddef.h>

/* Tell lwIP to skip system headers not available in freestanding mode */
#define LWIP_NO_INTTYPES_H     1
#define LWIP_NO_LIMITS_H       1
#define LWIP_NO_CTYPE_H        1
#define LWIP_NO_UNISTD_H       1

/* Provide format string macros that inttypes.h would normally define */
#define X8_F  "02x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "u"

/* Provide limits that limits.h would normally define */
#define INT_MAX     2147483647
#define SSIZE_MAX   INT_MAX

/* ssize_t for bare-metal */
typedef int ssize_t;

/* Protection type (used by SYS_LIGHTWEIGHT_PROT) */
typedef unsigned int sys_prot_t;

/* Random number generator - implemented in Rust */
extern unsigned int lwip_baremetal_rand(void);
#define LWIP_RAND() ((u32_t)lwip_baremetal_rand())

/* Diagnostics - disabled for bare-metal (no printf) */
#define LWIP_PLATFORM_DIAG(x) do { (void)0; } while(0)

/* Assertion - calls into Rust */
extern void lwip_platform_assert(const char *msg, int line, const char *file);
#define LWIP_PLATFORM_ASSERT(x) lwip_platform_assert(x, __LINE__, __FILE__)

/* Byte order - RISC-V is little-endian */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#endif /* __ARCH_CC_H__ */
