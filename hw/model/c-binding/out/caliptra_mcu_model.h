// Licensed under the Apache-2.0 license

#ifndef CALIPTRA_MCU_HW_MODEL_C_BINDING_CALIPTRA_MCU_MODEL_H
#define CALIPTRA_MCU_HW_MODEL_C_BINDING_CALIPTRA_MCU_MODEL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CALIPTRA_MCU_MODEL_STATUS_OK 0

#define CALIPTRA_MCU_MODEL_STATUS_INVALID_ARGUMENT -1

#define CALIPTRA_MCU_MODEL_STATUS_INIT_FAILED -2

#define CALIPTRA_MCU_MODEL_STATUS_OPERATION_FAILED -3

#define CALIPTRA_MCU_MODEL_STATUS_INVALID_OBF_KEY_SIZE -4

#define CALIPTRA_MCU_MODEL_STATUS_INVALID_VENDOR_PK_HASH_SIZE -5

#define CALIPTRA_MCU_MODEL_STATUS_PANICKED -6

#define CALIPTRA_MCU_MODEL_OBF_KEY_SIZE 32

#define CALIPTRA_MCU_MODEL_VENDOR_PK_HASH_SIZE 48

typedef struct caliptra_mcu_buffer {
  const uint8_t *data;
  uintptr_t len;
} caliptra_mcu_buffer;

typedef struct caliptra_mcu_model_init_params {
  /**
   * The contents of the Caliptra ROM.
   */
  struct caliptra_mcu_buffer caliptra_rom;
  /**
   * Caliptra firmware bundle.
   */
  struct caliptra_mcu_buffer caliptra_firmware;
  /**
   * SoC manifest.
   */
  struct caliptra_mcu_buffer soc_manifest;
  /**
   * The contents of the MCU ROM.
   */
  struct caliptra_mcu_buffer mcu_rom;
  /**
   * The contents of the MCU firmware.
   */
  struct caliptra_mcu_buffer mcu_firmware;
  /**
   * Initial contents of Caliptra DCCM SRAM.
   */
  struct caliptra_mcu_buffer caliptra_dccm;
  /**
   * Initial contents of Caliptra ICCM SRAM.
   */
  struct caliptra_mcu_buffer caliptra_iccm;
  /**
   * Optional initial contents of OTP memory. Set data to NULL to use defaults.
   */
  struct caliptra_mcu_buffer otp_memory;
  /**
   * Optional initial contents of DOT flash. Set data to NULL to use defaults.
   */
  struct caliptra_mcu_buffer dot_flash_initial_contents;
  /**
   * Optional initial contents of primary flash. Set data to NULL to use defaults.
   */
  struct caliptra_mcu_buffer primary_flash_initial_contents;
  /**
   * Optional 48-byte vendor public key hash. Set data to NULL to use defaults.
   */
  struct caliptra_mcu_buffer vendor_pk_hash;
  /**
   * Optional 32-byte Caliptra obfuscation key. Set data to NULL to use defaults.
   */
  struct caliptra_mcu_buffer optional_obf_key;
  /**
   * Optional I3C TCP port. Set to 0 to disable.
   */
  unsigned int i3c_port;
  bool active_mode;
  bool enable_mcu_uart_log;
  bool flash_boot;
  bool force_fuse_owner_pk_hash;
  bool active_i3c1;
  bool use_strap_secrets;
} caliptra_mcu_model_init_params;

typedef struct caliptra_mcu_model {
  uint8_t _unused[0];
} caliptra_mcu_model;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void cfi_panic_handler(uint32_t code);

/**
 * Create an unbooted MCU hardware model using default Rust InitParams values for
 * all fields not exposed in caliptra_mcu_model_init_params.
 *
 * Buffer pointers may be NULL only when len is 0. Optional buffers are disabled
 * by setting data to NULL and len to 0. The returned model must be destroyed by
 * caliptra_mcu_model_destroy().
 *
 * # Safety
 * `model` must be non-NULL. Non-NULL input buffers must point to at least `len`
 * bytes for the duration of this call.
 */
int caliptra_mcu_model_init_default(struct caliptra_mcu_model_init_params params,
                                    struct caliptra_mcu_model **model);

/**
 * # Safety
 * `model` must be either NULL or a pointer returned by caliptra_mcu_model_init_default.
 */
void caliptra_mcu_model_destroy(struct caliptra_mcu_model *model);

/**
 * Return a pointer to a NUL-terminated string describing the last operation
 * error for this model. The pointer remains valid until the next API call on the
 * model or until caliptra_mcu_model_destroy().
 *
 * # Safety
 * `model` must be NULL or a pointer returned by caliptra_mcu_model_init_default.
 */
const char *caliptra_mcu_model_last_error(struct caliptra_mcu_model *model);

/**
 * Boot the MCU model to the point where CPU execution can occur.
 *
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
int caliptra_mcu_model_boot(struct caliptra_mcu_model *model);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
int caliptra_mcu_model_step(struct caliptra_mcu_model *model);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
bool caliptra_mcu_model_ready_for_fw(struct caliptra_mcu_model *model);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
uint64_t caliptra_mcu_model_cycle_count(struct caliptra_mcu_model *model);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
bool caliptra_mcu_model_exit_requested(struct caliptra_mcu_model *model);

/**
 * Return a borrowed view of all UART output captured so far. The data pointer is
 * invalidated by the next API call that mutably accesses the model.
 *
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
struct caliptra_mcu_buffer caliptra_mcu_model_output_peek(struct caliptra_mcu_model *model);

/**
 * Read a 32-bit word from the MCU/Caliptra SoC-visible MMIO address space.
 *
 * # Safety
 * `model` and `data` must be non-NULL.
 */
int caliptra_mcu_model_mmio_read_u32(struct caliptra_mcu_model *model,
                                     unsigned int addr,
                                     unsigned int *data);

/**
 * Write a 32-bit word to the MCU/Caliptra SoC-visible MMIO address space.
 *
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
int caliptra_mcu_model_mmio_write_u32(struct caliptra_mcu_model *model,
                                      unsigned int addr,
                                      unsigned int data);

/**
 * Execute an MCU mailbox command and return a borrowed response buffer. If the
 * command completes without response data, `response` is set to { NULL, 0 }.
 * The response data pointer is invalidated by the next mailbox call or destroy.
 *
 * # Safety
 * `model` must be valid. `request.data` must be NULL only if `request.len` is 0.
 * `response` may be NULL if the caller only needs the status code.
 */
int caliptra_mcu_model_mailbox_execute(struct caliptra_mcu_model *model,
                                       unsigned int cmd,
                                       struct caliptra_mcu_buffer request,
                                       struct caliptra_mcu_buffer *response);

/**
 * Execute a Caliptra mailbox command through the SoC mailbox and return a
 * borrowed response buffer. If the command completes without response data,
 * `response` is set to { NULL, 0 }. The response data pointer is invalidated by
 * the next mailbox call or destroy.
 *
 * # Safety
 * `model` must be valid. `request.data` must be NULL only if `request.len` is 0.
 * `response` may be NULL if the caller only needs the status code.
 */
int caliptra_mcu_model_caliptra_mailbox_execute(struct caliptra_mcu_model *model,
                                                unsigned int cmd,
                                                struct caliptra_mcu_buffer request,
                                                struct caliptra_mcu_buffer *response);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
unsigned int caliptra_mcu_model_mci_flow_status(struct caliptra_mcu_model *model);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
unsigned int caliptra_mcu_model_mci_boot_checkpoint(struct caliptra_mcu_model *model);

/**
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
int caliptra_mcu_model_warm_reset(struct caliptra_mcu_model *model);

/**
 * Return a borrowed copy of DOT flash contents. The data pointer is invalidated
 * by the next caliptra_mcu_model_read_dot_flash() or
 * caliptra_mcu_model_read_otp_memory() call, or by destroy.
 *
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
struct caliptra_mcu_buffer caliptra_mcu_model_read_dot_flash(struct caliptra_mcu_model *model);

/**
 * Replace DOT flash contents with `data`.
 *
 * # Safety
 * `model` must be valid. `data.data` must be NULL only if `data.len` is 0.
 */
int caliptra_mcu_model_write_dot_flash(struct caliptra_mcu_model *model,
                                       struct caliptra_mcu_buffer data);

/**
 * Return a borrowed copy of OTP memory contents. The data pointer is invalidated
 * by the next caliptra_mcu_model_read_otp_memory() or
 * caliptra_mcu_model_read_dot_flash() call, or by destroy.
 *
 * # Safety
 * `model` must be a pointer returned by caliptra_mcu_model_init_default.
 */
struct caliptra_mcu_buffer caliptra_mcu_model_read_otp_memory(struct caliptra_mcu_model *model);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* CALIPTRA_MCU_HW_MODEL_C_BINDING_CALIPTRA_MCU_MODEL_H */
