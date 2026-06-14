// Licensed under the Apache-2.0 license

//! Platform implementation of the Caliptra VDM device-operations hook.
//!
//! [`CaliptraVdmHook`] is the emulator's [`CaliptraVdmCommands`] backend: it
//! performs the actual device work (Caliptra mailbox calls) for the Caliptra
//! VDM commands. The protocol/dispatch/framing all live in the
//! `mcu-spdm-lite-vdm-handler` lib; this hook only supplies the device ops.

use mcu_caliptra_api_lite::{get_attested_csr_ecc384, get_attested_csr_mldsa87, McuErrorCode};
use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};
use mcu_spdm_lite_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCommands, CaliptraVdmResult,
};

/// AsymAlgo wire encoding mirrored from caliptra-api (`AsymAlgo::EccP384 = 1`,
/// `MlDsa87 = 2`); kept local so the hook does not pull in caliptra-api.
const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

/// Emulator Caliptra VDM device-operations backend.
pub struct CaliptraVdmHook;

impl CaliptraVdmCommands for CaliptraVdmHook {
    async fn firmware_version<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        _area_index: u32,
        _scratch: &A,
        _io: &I,
        _out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        // No firmware-version device source is wired on this platform yet.
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn export_attested_csr<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let result = match algorithm {
            ALGO_ECC_P384 => get_attested_csr_ecc384(device_key_id, nonce, out).await,
            ALGO_MLDSA87 => get_attested_csr_mldsa87(device_key_id, nonce, out).await,
            _ => return Err(CaliptraCompletionCode::InvalidParameter),
        };
        result.map_err(map_mcu_err)
    }
}

fn map_mcu_err(e: McuErrorCode) -> CaliptraCompletionCode {
    use mcu_error::codes;
    if e == codes::MAILBOX_BUSY {
        CaliptraCompletionCode::CaliptraMailboxBusy
    } else if e == codes::INVARIANT {
        CaliptraCompletionCode::OperationFailed
    } else if e.domain() == mcu_error::domain::MEMORY {
        CaliptraCompletionCode::InsufficientResources
    } else {
        CaliptraCompletionCode::GeneralError
    }
}
