// Licensed under the Apache-2.0 license

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "caliptra_mcu_model.h"

int main(void) {
    struct caliptra_mcu_model *model = 0;
    struct caliptra_mcu_model_init_params params = {0};
    struct caliptra_mcu_buffer response = {0};
    unsigned int word = 0;

    // This smoke test primarily verifies that C consumers can include the
    // generated header and link the static library. Empty firmware inputs are
    // accepted by the C ABI but are not expected to produce a bootable model.
    (void)caliptra_mcu_model_init_default(params, &model);
    (void)caliptra_mcu_model_last_error(model);
    (void)caliptra_mcu_model_ready_for_fw(model);
    (void)caliptra_mcu_model_cycle_count(model);
    (void)caliptra_mcu_model_output_peek(model);

    // Keep the rest of the API referenced so link errors are caught, but do not
    // exercise invalid MMIO/mailbox accesses unless explicitly requested.
    if (getenv("CALIPTRA_MCU_C_BINDING_EXERCISE_ALL") != 0) {
        (void)caliptra_mcu_model_mmio_read_u32(model, 0, &word);
        (void)caliptra_mcu_model_mmio_write_u32(model, 0, word);
        (void)caliptra_mcu_model_mailbox_execute(model, 0, params.mcu_rom, &response);
        (void)caliptra_mcu_model_caliptra_mailbox_execute(model, 0, params.mcu_rom, &response);
        (void)caliptra_mcu_model_mci_flow_status(model);
        (void)caliptra_mcu_model_mci_boot_checkpoint(model);
        (void)caliptra_mcu_model_read_dot_flash(model);
        (void)caliptra_mcu_model_read_otp_memory(model);
    }

    caliptra_mcu_model_destroy(model);

    puts("Caliptra MCU HW model C binding smoke test linked successfully");
    return 0;
}
