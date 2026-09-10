// Licensed under the Apache-2.0 license

/**
 * @file sys_arch.h
 * Bare-metal NO_SYS=1 port - minimal OS abstraction
 *
 * With NO_SYS=1, lwIP does not use semaphores, mutexes,
 * mailboxes, or threads. Only sys_now() is needed.
 */

#ifndef __ARCH_SYS_ARCH_H__
#define __ARCH_SYS_ARCH_H__

/* No OS abstractions needed for NO_SYS=1 mode */

#endif /* __ARCH_SYS_ARCH_H__ */
