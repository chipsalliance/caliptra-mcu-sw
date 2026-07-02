// Licensed under the Apache-2.0 license

//! Platform implementation of the Caliptra VDM device-operations hook.
//!
//! [`CaliptraVdmHook`] is the emulator's [`CaliptraVdmCommands`] backend: it
//! performs the actual device work (Caliptra mailbox calls) for the Caliptra
//! VDM commands. The protocol/dispatch/framing all live in the
//! `caliptra-mcu-spdm-vdm-handler` lib; this hook only supplies the device ops.

extern crate alloc;

use alloc::boxed::Box;
use arrayvec::ArrayVec;
use caliptra_mcu_common_commands::{
    CaliptraCompletionCode as CommonCompletionCode, GetLogResult, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError, PayloadStream};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCommands, CaliptraVdmLogResult, CaliptraVdmResult,
};
use constant_time_eq::constant_time_eq;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{
    cm_hmac, cm_import, fe_prog, get_attested_csr_ecc384, get_attested_csr_mldsa87,
    request_debug_unlock_challenge, rng_generate, ApiAlloc, CmKeyUsage, McuErrorCode,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
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

    async fn request_debug_unlock<A: SpdmPalAlloc>(
        &self,
        unlock_level: u8,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let needed = DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE;
        if out.len() < needed {
            return Err(CaliptraCompletionCode::InsufficientResources);
        }

        request_debug_unlock_challenge(scratch, unlock_level, out)
            .await
            .map_err(map_mcu_err)
    }

    async fn authorize_debug_unlock_token<A: SpdmPalAlloc>(
        &self,
        token_data: &[u8],
        scratch: &A,
    ) -> CaliptraVdmResult<()> {
        let cmd = PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD;
        // The host sends the production debug-unlock token payload in Caliptra RT
        // mailbox format, including the MailboxReqHeader/checksum, and large
        // requests are streamed directly to the mailbox. Do not synthesize
        // another checksum header here or the mailbox would receive
        // `[new_checksum || host_checksum || token]`.
        let mut token_stream = SlicePayloadStream::new(token_data);
        let mut resp_buf = ApiAlloc::alloc(scratch, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN)
            .map_err(map_mcu_err)?;

        Mailbox::<DefaultSyscalls>::new()
            .execute_with_payload_stream(cmd, None, &mut token_stream, &mut resp_buf)
            .await
            .map_err(map_mailbox_error)?;
        Ok(())
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

    async fn get_dot_backup_blob<A: SpdmPalAlloc>(
        &self,
        _scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let dot_blob_size = caliptra_mcu_common_commands::DOT_BLOB_SIZE;
        if out.len() < dot_blob_size {
            return Err(CaliptraCompletionCode::InsufficientResources);
        }

        caliptra_mcu_libsyscall_caliptra::dot_flash::DotFlash::<DefaultSyscalls>::new()
            .read(0, &mut out[..dot_blob_size])
            .map_err(map_dot_flash_error)?;
        Ok(dot_blob_size)
    }
}

struct SlicePayloadStream<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SlicePayloadStream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

#[async_trait::async_trait(?Send)]
impl PayloadStream for SlicePayloadStream<'_> {
    fn size(&self) -> usize {
        self.data.len()
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        let remaining = self.data.len().saturating_sub(self.offset);
        if remaining == 0 {
            return Ok(0);
        }
        let n = remaining.min(buffer.len());
        buffer[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
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

fn map_mailbox_error(e: MailboxError) -> CaliptraCompletionCode {
    match e {
        MailboxError::ErrorCode(ErrorCode::Busy) => CaliptraCompletionCode::CaliptraMailboxBusy,
        MailboxError::ErrorCode(_) | MailboxError::MailboxError(_) => {
            CaliptraCompletionCode::OperationFailed
        }
    }
}

fn map_dot_flash_error(e: ErrorCode) -> CaliptraCompletionCode {
    match e {
        ErrorCode::NoSupport | ErrorCode::NoDevice | ErrorCode::Uninstalled => {
            CaliptraCompletionCode::UnsupportedOperation
        }
        ErrorCode::NoMem | ErrorCode::Size => CaliptraCompletionCode::InsufficientResources,
        ErrorCode::Invalid => CaliptraCompletionCode::InvalidParameter,
        ErrorCode::Busy => CaliptraCompletionCode::ResourceUnavailable,
        _ => CaliptraCompletionCode::OperationFailed,
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
