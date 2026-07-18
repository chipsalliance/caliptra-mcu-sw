// Licensed under the Apache-2.0 license

//! Measurement boot-initialization wiring.
//!
//! Cold boot rotates the MCU Runtime DPE context off the default handle.
//! Attestation certificate and signing paths use Measurement API so DPE handle
//! rotations are persisted before each operation returns.

use caliptra_mcu_libsyscall_caliptra::mci::{mci_reg::RESET_REASON, Mci as MciSyscall};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_measurement_api::BootKind;
use caliptra_mcu_spdm_pal::{BitmapAllocator, BITMAP_SLOT_SIZE};

extern crate alloc;
use alloc::vec::Vec;
#[cfg(not(feature = "userspace-log"))]
use core::fmt::Write as _;
use core::ptr::NonNull;

/// `FW_HITLESS_UPD_RESET` bit in the MCI `RESET_REASON` register.
const RESET_REASON_FW_HITLESS_UPD_RESET_MASK: u32 = 0x1;
/// `FW_BOOT_UPD_RESET` bit in the MCI `RESET_REASON` register.
const RESET_REASON_FW_BOOT_UPD_RESET_MASK: u32 = 0x2;
/// `WARM_RESET` bit in the MCI `RESET_REASON` register.
const RESET_REASON_WARM_RESET_MASK: u32 = 0x4;
const RESET_REASON_SUPPORTED_MASK: u32 = RESET_REASON_FW_HITLESS_UPD_RESET_MASK
    | RESET_REASON_FW_BOOT_UPD_RESET_MASK
    | RESET_REASON_WARM_RESET_MASK;

/// Scratch pool (bytes) backing the boot-init SHA / DPE mailbox request buffers.
const BOOT_INIT_SCRATCH_SIZE: usize = 4096;
const BOOT_INIT_SCRATCH_SLOTS: usize = BOOT_INIT_SCRATCH_SIZE / BITMAP_SLOT_SIZE;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct BootScratchSlot([u8; BITMAP_SLOT_SIZE]);

/// Initialize measurement state before any measurement consumer starts.
///
/// Classifies the reset as cold boot or MCU hitless update from `RESET_REASON`,
/// then runs `measurement_boot_init` through a temporary bitmap allocator that
/// backs the mailbox request buffers. The allocator is dropped once boot init
/// completes; the [`MeasurementApi`] instance is published to [`MEASUREMENT_API`]
/// for later consumers, and the persistent measurement state lives in the DPE
/// Handle Storage and Software PCR Storage capsules.
pub(crate) async fn boot_init(
    attestation_manifest: &'static [u8],
    soc_image_load_fw_ids: &'static [u32],
) {
    let boot_kind = match reset_boot_kind() {
        Ok(kind) => kind,
        Err(_) => {
            log_boot_init_error(BootInitLog::Reset);
            return;
        }
    };

    let mut scratch = Vec::new();
    if scratch.try_reserve_exact(BOOT_INIT_SCRATCH_SLOTS).is_err() {
        log_boot_init_error(BootInitLog::Scratch);
        return;
    }
    scratch.resize(
        BOOT_INIT_SCRATCH_SLOTS,
        BootScratchSlot([0; BITMAP_SLOT_SIZE]),
    );
    let Some(scratch_ptr) = NonNull::new(scratch.as_mut_ptr().cast::<u8>()) else {
        log_boot_init_error(BootInitLog::Scratch);
        return;
    };
    // SAFETY: `scratch_ptr` points at aligned heap memory owned by `scratch`.
    // `scratch` is kept alive until `init` returns and no allocator buffers
    // escape that call.
    let allocator = unsafe { BitmapAllocator::new(scratch_ptr, BOOT_INIT_SCRATCH_SIZE) };

    if caliptra_mcu_measurement_api::init(
        attestation_manifest,
        soc_image_load_fw_ids,
        boot_kind,
        &allocator,
    )
    .await
    .is_err()
    {
        log_boot_init_error(BootInitLog::Init);
    }
}

enum BootInitLog {
    Reset,
    Scratch,
    Init,
}

fn log_boot_init_error(error: BootInitLog) {
    let mut cw = Console::<DefaultSyscalls>::writer();
    match error {
        BootInitLog::Reset => crate::log_error!(cw, "[meas] reset"),
        BootInitLog::Scratch => crate::log_error!(cw, "[meas] scratch"),
        BootInitLog::Init => crate::log_error!(cw, "[meas] init"),
    }
}

/// Classify the current reset as cold boot or MCU hitless update.
fn reset_boot_kind() -> Result<BootKind, ErrorCode> {
    let mci = MciSyscall::<DefaultSyscalls>::new();
    let reason = mci.read(RESET_REASON, 0)?;
    decode_reset_reason(reason).ok_or(ErrorCode::Invalid)
}

fn decode_reset_reason(reason: u32) -> Option<BootKind> {
    if reason & !RESET_REASON_SUPPORTED_MASK != 0 {
        return None;
    }
    let hitless = reason & RESET_REASON_FW_HITLESS_UPD_RESET_MASK != 0;
    let boot_update = reason & RESET_REASON_FW_BOOT_UPD_RESET_MASK != 0;
    if hitless && boot_update {
        return None;
    }
    if hitless {
        Some(BootKind::HitlessUpdate)
    } else {
        Some(BootKind::ColdBoot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_reason_zero_is_cold_boot() {
        assert_eq!(decode_reset_reason(0), Some(BootKind::ColdBoot));
    }

    #[test]
    fn reset_reason_supported_non_hitless_values_are_cold_boot() {
        assert_eq!(
            decode_reset_reason(RESET_REASON_WARM_RESET_MASK),
            Some(BootKind::ColdBoot)
        );
        assert_eq!(
            decode_reset_reason(RESET_REASON_FW_BOOT_UPD_RESET_MASK),
            Some(BootKind::ColdBoot)
        );
        assert_eq!(
            decode_reset_reason(RESET_REASON_FW_BOOT_UPD_RESET_MASK | RESET_REASON_WARM_RESET_MASK),
            Some(BootKind::ColdBoot)
        );
    }

    #[test]
    fn reset_reason_hitless_values_are_hitless_update() {
        assert_eq!(
            decode_reset_reason(RESET_REASON_FW_HITLESS_UPD_RESET_MASK),
            Some(BootKind::HitlessUpdate)
        );
        assert_eq!(
            decode_reset_reason(
                RESET_REASON_FW_HITLESS_UPD_RESET_MASK | RESET_REASON_WARM_RESET_MASK
            ),
            Some(BootKind::HitlessUpdate)
        );
    }

    #[test]
    fn reset_reason_unsupported_or_ambiguous_values_are_rejected() {
        assert_eq!(decode_reset_reason(0x8), None);
        assert_eq!(
            decode_reset_reason(
                RESET_REASON_FW_HITLESS_UPD_RESET_MASK | RESET_REASON_FW_BOOT_UPD_RESET_MASK
            ),
            None
        );
    }
}
