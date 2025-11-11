// Licensed under the Apache-2.0 license

#ifndef CALIPTRA_TEST_UTILS_H
#define CALIPTRA_TEST_UTILS_H

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Forward declaration to resolve circular reference in auto-generated header
struct CMailboxDriver;

// Include auto-generated comprehensive header for all types
#include "../include/caliptra_util_host.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Forward declarations
struct CaliptraTransport;

/**
 * Forward declaration for CMailboxDriver  
 */
struct CMailboxDriver;




struct CMailboxDriver;
typedef struct CMailboxDriver CMailboxDriver;

struct CMailboxDriverVTable;
typedef struct CMailboxDriverVTable CMailboxDriverVTable;

// Test utility functions for creating mock drivers
enum CaliptraError caliptra_mock_mailbox_driver_create(uint16_t device_id,
                                                      struct CMailboxDriver **driver);

enum CaliptraError caliptra_mock_mailbox_driver_destroy(struct CMailboxDriver *driver);

// Transport functions are provided by the auto-generated header



#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* CALIPTRA_TEST_UTILS_H */