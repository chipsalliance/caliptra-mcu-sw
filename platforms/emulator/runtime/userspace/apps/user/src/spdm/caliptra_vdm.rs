// Licensed under the Apache-2.0 license

//! Platform implementation of the Caliptra VDM device-operations hook.
//!
//! [`CaliptraVdmHook`] is the emulator's [`CaliptraVdmCommands`] backend: it
//! performs the actual device work (Caliptra mailbox calls) for the Caliptra
//! VDM commands. The protocol/dispatch/framing all live in the
//! `mcu-spdm-lite-vdm-handler` lib; this hook only supplies the device ops.

use arrayvec::ArrayVec;
use caliptra_mcu_common_commands::{CaliptraCompletionCode as CommonCompletionCode, GetLogResult};
use constant_time_eq::constant_time_eq;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{
    cm_hmac, cm_import, fe_prog, get_attested_csr_ecc384, get_attested_csr_mldsa87, rng_generate,
    ApiAlloc, CmKeyUsage, McuErrorCode,
};
use mcu_spdm_lite_traits::SpdmPalAlloc;
use mcu_spdm_lite_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCommands, CaliptraVdmLogResult, CaliptraVdmResult,
};

/// AsymAlgo wire encoding (`EccP384 = 1`, `MlDsa87 = 2`), mirrored locally so
/// the hook does not depend on caliptra-api.
const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

/// HMAC command ID used by the host for the FE_PROG authorized sub-command.
const FE_PROG_CMD_ID: u32 = 0x4D43_4650;
/// Symmetric test HMAC key used by the emulator validator path.
const TEST_AUTH_CMD_HMAC_KEY: [u8; 48] = [
    0x72, 0xec, 0x12, 0x02, 0x77, 0x69, 0xb9, 0xdc, 0x04, 0xbd, 0xd0, 0xc0, 0x86, 0xca, 0x1b, 0x20,
    0x2f, 0x47, 0x1e, 0xee, 0xf2, 0x8c, 0x2d, 0xa8, 0xc5, 0x4c, 0x75, 0xc2, 0x48, 0xa6, 0x80, 0x0a,
    0x11, 0xbf, 0xd5, 0xcd, 0x09, 0xed, 0x57, 0x0c, 0xb4, 0xc2, 0xa1, 0x37, 0x6b, 0xa2, 0xcb, 0xcd,
];

static AUTH_CHALLENGE: Mutex<CriticalSectionRawMutex, Option<[u8; 32]>> = Mutex::new(None);

/// Emulator Caliptra VDM device-operations backend.
pub struct CaliptraVdmHook;

impl CaliptraVdmCommands for CaliptraVdmHook {
    async fn get_log<A: SpdmPalAlloc>(
        &self,
        log_type: u32,
        _scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<CaliptraVdmLogResult> {
        let result = match log_type {
            0 => crate::caliptra_cmd_handler::debug_log::drain(out)
                .await
                .map_err(map_common_completion),
            1 => Err(CaliptraCompletionCode::UnsupportedOperation),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }?;
        let GetLogResult {
            bytes_written,
            more_data,
        } = result;
        Ok(CaliptraVdmLogResult {
            bytes_written,
            more_data,
        })
    }

    async fn clear_log<A: SpdmPalAlloc>(
        &self,
        log_type: u32,
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        match log_type {
            0 => crate::caliptra_cmd_handler::debug_log::clear()
                .await
                .map_err(map_common_completion),
            1 => Err(CaliptraCompletionCode::UnsupportedOperation),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }

    async fn export_attested_csr<A: SpdmPalAlloc>(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        _scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let result = match algorithm {
            ALGO_ECC_P384 => get_attested_csr_ecc384(device_key_id, nonce, out).await,
            ALGO_MLDSA87 => get_attested_csr_mldsa87(device_key_id, nonce, out).await,
            _ => return Err(CaliptraCompletionCode::InvalidParameter),
        };
        result.map_err(map_mcu_err)
    }

    async fn get_auth_challenge<A: SpdmPalAlloc>(
        &self,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let mut challenge = [0u8; 32];
        rng_generate(scratch, &mut challenge)
            .await
            .map_err(map_mcu_err)?;
        *AUTH_CHALLENGE.lock().await = Some(challenge);
        copy_bytes(&challenge, out)
    }

    async fn program_field_entropy<A: SpdmPalAlloc>(
        &self,
        partition: u32,
        mac: &[u8; 48],
        scratch: &A,
    ) -> CaliptraVdmResult<()> {
        verify_fe_prog_mac(scratch, partition, mac).await?;
        fe_prog(scratch, partition).await.map_err(map_mcu_err)
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

fn copy_bytes(src: &[u8], out: &mut [u8]) -> CaliptraVdmResult<usize> {
    if src.len() > out.len() {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }
    for (d, s) in out.iter_mut().zip(src) {
        *d = *s;
    }
    Ok(src.len())
}

async fn verify_fe_prog_mac<A: ApiAlloc>(
    scratch: &A,
    partition: u32,
    mac: &[u8; 48],
) -> CaliptraVdmResult<()> {
    let challenge = AUTH_CHALLENGE
        .lock()
        .await
        .take()
        .ok_or(CaliptraCompletionCode::AccessDenied)?;

    let cmk = cm_import(scratch, CmKeyUsage::Hmac, &TEST_AUTH_CMD_HMAC_KEY)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    let mut hmac_input = ArrayVec::<u8, 256>::new();
    hmac_input
        .try_extend_from_slice(&FE_PROG_CMD_ID.to_be_bytes())
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    hmac_input
        .try_extend_from_slice(&partition.to_le_bytes())
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    hmac_input
        .try_extend_from_slice(&challenge)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;

    let mut computed_mac = [0u8; 48];
    let mac_len = cm_hmac(scratch, &cmk, hmac_input.as_slice(), &mut computed_mac)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if mac_len != 48 {
        return Err(CaliptraCompletionCode::OperationFailed);
    }
    if constant_time_eq(&computed_mac, mac) {
        Ok(())
    } else {
        Err(CaliptraCompletionCode::AccessDenied)
    }
}

fn map_common_completion(code: CommonCompletionCode) -> CaliptraCompletionCode {
    match code {
        CommonCompletionCode::Success => CaliptraCompletionCode::Success,
        CommonCompletionCode::GeneralError => CaliptraCompletionCode::GeneralError,
        CommonCompletionCode::InvalidParameter => CaliptraCompletionCode::InvalidParameter,
        CommonCompletionCode::InvalidLength => CaliptraCompletionCode::InvalidLength,
        CommonCompletionCode::InvalidIdentifier => CaliptraCompletionCode::InvalidIdentifier,
        CommonCompletionCode::OperationFailed => CaliptraCompletionCode::OperationFailed,
        CommonCompletionCode::InsufficientResources => {
            CaliptraCompletionCode::InsufficientResources
        }
        CommonCompletionCode::UnsupportedOperation => CaliptraCompletionCode::UnsupportedOperation,
        CommonCompletionCode::DeviceNotReady => CaliptraCompletionCode::DeviceNotReady,
        CommonCompletionCode::InvalidCommandVersion => {
            CaliptraCompletionCode::InvalidCommandVersion
        }
        CommonCompletionCode::InvalidPayloadSize => CaliptraCompletionCode::InvalidPayloadSize,
        CommonCompletionCode::Timeout => CaliptraCompletionCode::Timeout,
        CommonCompletionCode::AccessDenied => CaliptraCompletionCode::AccessDenied,
        CommonCompletionCode::ResourceUnavailable => CaliptraCompletionCode::ResourceUnavailable,
        CommonCompletionCode::PolicyViolation => CaliptraCompletionCode::PolicyViolation,
        CommonCompletionCode::InvalidState => CaliptraCompletionCode::InvalidState,
        CommonCompletionCode::CaliptraMailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
        CommonCompletionCode::CaliptraBufferTooSmall => {
            CaliptraCompletionCode::CaliptraBufferTooSmall
        }
    }
}
