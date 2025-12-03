/*++

Licensed under the Apache-2.0 license.

File Name:

    device_ownership_transfer.rs

Abstract:

    Handles Device Ownership Transfer (DOT) flows in the ROM.

--*/

use crate::fuses::OwnerPkHash;
use caliptra_api::mailbox::CmStableKeyType;
use mcu_error::{McuError, McuResult};
use registers_generated::fuses::Fuses;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, Default)]
pub struct DotFuses {}

/// The DOT blob data structure containing ownership credentials and locking keys.
///
/// This cryptographically authenticated structure is stored in external flash
/// and contains the CAK and LAK, sealed with the DOT_EFFECTIVE_KEY via HMAC.
/// The blob persists ownership across power cycles when in the Locked state.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct DotBlob {
    /// Version or format identifier for the DOT blob structure
    pub version: u32,
    // TODO: add other fields
    /// HMAC tag authenticating the entire DOT blob
    /// Computed using DOT_EFFECTIVE_KEY.
    pub hmac: [u32; 16],
}

/// Main Device Ownership Transfer flow executed during ROM boot.
///
/// This function orchestrates the DOT process, which includes:
/// 1. Deriving the DOT_EFFECTIVE_KEY from hardware secrets and fuse state
/// 2. Verifying the DOT blob authenticity using HMAC
/// 3. Burning DOT fuses if a state transition is pending
/// 4. Determining the final owner based on fuse state and DOT blob
///
/// # Arguments
/// * `main_fuses` - Main fuse data.
/// * `dot_fuses` - DOT fuse data.
/// * `blob` - DOT blob loaded from storage.
/// * `stable_key_type` - The type of stable key to derive to verify the DOT blob with.
///
/// # Returns
/// * `Ok(OwnerPkHash)` - The determined owner's public key hash on success.
/// * `Err(McuError)` - If any step of the DOT flow fails.
pub fn dot_flow(
    _main_fuses: &Fuses,
    _dot_fuses: &DotFuses,
    _blob: &DotBlob,
    _stable_key_type: CmStableKeyType,
) -> McuResult<Option<OwnerPkHash>> {
    romtime::println!("[mcu-rom] Performing Device Ownership Transfer flows");
    // TODO: implement all the steps
    // for now, we just fail
    romtime::println!("[mcu-rom] DOT blob HMAC did not match");
    Err(McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR)
}
