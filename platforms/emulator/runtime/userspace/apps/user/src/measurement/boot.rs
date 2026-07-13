// Licensed under the Apache-2.0 license

//! Measurement boot-initialization wiring.
//!
//! Gated behind the `measurement-boot-init` cargo feature (off by default).
//!
//! Cold boot rotates the MCU Runtime DPE context off the default handle. The
//! current SPDM evidence / certificate path still signs with the DPE *default*
//! context handle (which DPE keeps sticky), so enabling boot init before that
//! path is rewired to track the rotated handle would break attestation:
//! `CertifyKey` / `Sign` on a non-default context roll the handle each call.
//! Enable this feature together with the SPDM handle-lifecycle rewire.

use caliptra_mcu_libsyscall_caliptra::mci::{mci_reg::RESET_REASON, Mci as MciSyscall};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_measurement_api::api::MeasurementApi;
use caliptra_mcu_measurement_api::BootKind;
use caliptra_mcu_spdm_pal::{BitmapAllocator, BITMAP_SLOT_SIZE};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_error::McuErrorCode;

#[allow(unused_imports)]
use core::fmt::Write as _;
use core::ptr::NonNull;

use super::attestation_manifest_bytes;

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

/// Single shared Measurement API instance.
///
/// Initialized once by [`boot_init`] and shared by all measurement consumers.
/// The async mutex serializes concurrent access: each measurement operation is
/// a multi-step async sequence over shared DPE/PCR capsule state, so a caller
/// holds the lock for the whole operation. `None` until boot init runs (or if
/// manifest parsing failed).
pub(crate) static MEASUREMENT_API: Mutex<
    CriticalSectionRawMutex,
    Option<MeasurementApi<'static, DefaultSyscalls>>,
> = Mutex::new(None);

/// Initialize measurement state before any measurement consumer starts.
///
/// Classifies the reset as cold boot or MCU hitless update from `RESET_REASON`,
/// then runs `measurement_boot_init` through a temporary bitmap allocator that
/// backs the mailbox request buffers. The allocator is dropped once boot init
/// completes; the [`MeasurementApi`] instance is published to [`MEASUREMENT_API`]
/// for later consumers, and the persistent measurement state lives in the DPE
/// Handle Storage and Software PCR Storage capsules.
pub(crate) async fn boot_init() {
    let mut cw = Console::<DefaultSyscalls>::writer();

    let boot_kind = match reset_boot_kind() {
        Ok(kind) => kind,
        Err(_) => {
            crate::log_error!(
                cw,
                "[measurement] RESET_REASON read/decode failed; skipping boot init"
            );
            return;
        }
    };

    #[repr(C, align(64))]
    struct ScratchBuf([u8; BOOT_INIT_SCRATCH_SIZE]);
    static mut BOOT_INIT_SCRATCH: ScratchBuf = ScratchBuf([0u8; BOOT_INIT_SCRATCH_SIZE]);
    // SAFETY: `boot_init` runs once at startup before any task that could use
    // this buffer is spawned, so it is the sole owner of `BOOT_INIT_SCRATCH`.
    let scratch_ptr: NonNull<u8> =
        unsafe { NonNull::new_unchecked(BOOT_INIT_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);
    // SAFETY: `scratch_ptr` points at `'static`, exclusively-owned memory of
    // `BOOT_INIT_SCRATCH_SIZE` bytes.
    let allocator = unsafe { BitmapAllocator::new(scratch_ptr, BOOT_INIT_SCRATCH_SIZE) };

    let api = match MeasurementApi::<DefaultSyscalls>::new(attestation_manifest_bytes()) {
        Ok(api) => api,
        Err(e) => {
            crate::log_error!(
                cw,
                "[measurement] attestation manifest invalid: 0x{}",
                crate::Hex32(u32::from(McuErrorCode::from(e)))
            );
            return;
        }
    };

    // Publish the single shared instance, then drive boot init while holding the
    // lock. No consumer task is spawned yet, so there is no contention here;
    // W6+ consumers serialize through this same lock.
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard.insert(api);
    if let Err(e) = api.measurement_boot_init(boot_kind, &allocator).await {
        crate::log_error!(
            cw,
            "[measurement] boot init failed: 0x{}",
            crate::Hex32(u32::from(McuErrorCode::from(e)))
        );
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
