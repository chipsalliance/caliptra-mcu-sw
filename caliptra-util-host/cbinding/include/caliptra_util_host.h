// Licensed under the Apache-2.0 license

/* Auto-generated from Rust caliptra-util-host library */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C-compatible error type that can be exported
 */
typedef enum CaliptraError {
  Success = 0,
  Unknown = 1,
  InvalidArgument = 2,
  Timeout = 3,
  NotSupported = 4,
  Transport = 5,
  Protocol = 6,
  Device = 7,
  Memory = 8,
  Busy = 9,
  State = 10,
  IO = 11,
} CaliptraError;

/**
 * Protocol types supported by the core layer (from design document)
 */
typedef enum CaliptraProtocolType {
  Mailbox = 0,
  MctpVdm = 1,
  Custom = 2,
} CaliptraProtocolType;

/**
 * Device session context using dynamic dispatch with borrowed transport
 */
typedef struct CaliptraSession CaliptraSession;

/**
 * Get device ID response
 * Clean format containing only the essential device identification fields
 */
typedef struct GetDeviceIdResponse {
  /**
   * Vendor ID (LSB)
   */
  uint16_t vendor_id;
  /**
   * Device ID (LSB)
   */
  uint16_t device_id;
  /**
   * Subsystem Vendor ID (LSB)
   */
  uint16_t subsystem_vendor_id;
  /**
   * Subsystem ID (LSB)
   */
  uint16_t subsystem_id;
} GetDeviceIdResponse;

/**
 * Opaque transport handle (from design document)
 */
typedef struct CaliptraTransport {
  uint8_t _private[0];
} CaliptraTransport;

/**
 * C function pointer types for custom transport implementation
 */
typedef enum CaliptraError (*CTransportSendFn)(void *ctx,
                                               uint32_t command_id,
                                               const uint8_t *data,
                                               uintptr_t len);

typedef enum CaliptraError (*CTransportReceiveFn)(void *ctx,
                                                  uint8_t *buffer,
                                                  uintptr_t buffer_len,
                                                  uintptr_t *received_len);

typedef enum CaliptraError (*CTransportConnectFn)(void *ctx);

typedef enum CaliptraError (*CTransportDisconnectFn)(void *ctx);

typedef bool (*CTransportIsConnectedFn)(void *ctx);

typedef void (*CTransportDestroyFn)(void *ctx);

/**
 * C Transport vtable - function pointers for transport operations
 */
typedef struct CTransportVTable {
  CTransportSendFn send;
  CTransportReceiveFn receive;
  CTransportConnectFn connect;
  CTransportDisconnectFn disconnect;
  CTransportIsConnectedFn is_connected;
  CTransportDestroyFn destroy;
} CTransportVTable;

/**
 * Function pointer types for MailboxDriver implementation in C
 */
typedef struct CMailboxDriverVTable {
  enum CaliptraError (*send_command)(struct CMailboxDriver *driver,
                                     uint32_t external_cmd,
                                     const uint8_t *payload,
                                     uintptr_t payload_len,
                                     const uint8_t **response,
                                     uintptr_t *response_len);
  bool (*is_ready)(struct CMailboxDriver *driver);
  enum CaliptraError (*connect)(struct CMailboxDriver *driver);
  enum CaliptraError (*disconnect)(struct CMailboxDriver *driver);
} CMailboxDriverVTable;

/**
 * Complete C MailboxDriver implementation
 */
typedef struct CMailboxDriver {
  struct CMailboxDriverVTable *vtable;
  uint16_t device_id;
  uint16_t vendor_id;
  uint16_t subsystem_vendor_id;
  uint16_t subsystem_id;
  bool ready;
  bool connected;
  uint8_t response_buffer[32];
} CMailboxDriver;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

enum CaliptraError caliptra_cmd_get_device_id(struct CaliptraSession *session,
                                              struct GetDeviceIdResponse *device_id);

/**
 * Get device identification information (C-exportable version)
 *
 * This function can be called from C code and takes a direct session pointer.
 *
 * # Parameters
 *
 * - `session_ptr`: Direct pointer to CaliptraSession
 * - `device_id`: Pointer to store the device ID response
 *
 * # Returns
 *
 * - `CaliptraError::Success` on success
 * - Error code on failure
 *
 * # Safety
 *
 * This function is unsafe because it works with raw pointers.
 * The caller must ensure both pointers are valid.
 */
enum CaliptraError caliptra_cmd_get_device_id_c_impl(struct CaliptraSession *session_ptr,
                                                     struct GetDeviceIdResponse *device_id);

/**
 * Create a new Caliptra session with transport
 *
 * # Parameters
 *
 * - `transport`: Transport instance to use for communication
 * - `session_handle`: Pointer to store the created session handle
 *
 * # Returns
 *
 * - `CaliptraError::Success` on success
 * - Error code on failure
 *
 * Create a new Caliptra session with explicit protocol type
 *
 * # Parameters
 *
 * - `transport`: Transport instance to use for communication
 * - `protocol_type`: Protocol type that determines how to interpret the transport
 * - `session_handle`: Pointer to store the created session handle
 *
 * # Returns
 *
 * - `CaliptraError::Success` on success
 * - Error code on failure
 */
enum CaliptraError caliptra_session_create_with_protocol(struct CaliptraTransport *transport,
                                                         enum CaliptraProtocolType protocol_type,
                                                         struct CaliptraSession **session);

/**
 * Connect to the Caliptra device
 *
 * # Parameters
 *
 * - `session_handle`: Session handle obtained from `caliptra_session_create`
 *
 * # Returns
 *
 * - `CaliptraError::Success` on success
 * - Error code on failure
 */
enum CaliptraError caliptra_session_connect(struct CaliptraSession *session);

/**
 * Disconnect from the Caliptra device
 *
 * # Parameters
 *
 * - `session_handle`: Session handle
 *
 * # Returns
 *
 * - `CaliptraError::Success` on success
 * - Error code on failure
 */
enum CaliptraError caliptra_session_disconnect(struct CaliptraSession *session);

/**
 * Destroy a Caliptra session and free associated resources
 *
 * # Parameters
 *
 * - `session_handle`: Session handle to destroy
 *
 * # Returns
 *
 * - `CaliptraError::Success` on success
 * - Error code on failure
 */
enum CaliptraError caliptra_session_destroy(struct CaliptraSession *session);

/**
 * Destroy transport instance (from design document)
 */
enum CaliptraError caliptra_transport_destroy(struct CaliptraTransport *transport);

/**
 * Create a transport from C function pointers (C-exportable)
 */
enum CaliptraError caliptra_transport_create_from_c_vtable(const struct CTransportVTable *vtable,
                                                           void *context,
                                                           struct CaliptraTransport **transport);

/**
 * Create a transport from a C MailboxDriver
 */
enum CaliptraError caliptra_transport_create_from_c_mailbox_driver(struct CMailboxDriver *c_driver,
                                                                   struct CaliptraTransport **transport);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
