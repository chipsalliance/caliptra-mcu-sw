// Licensed under the Apache-2.0 license

//! Platform implementation of the Caliptra VDM device-operations hook.
//!
//! [`CaliptraVdmHook`] is the emulator's [`CaliptraVdmCommands`] backend: it
//! performs the actual device work (Caliptra mailbox calls) for the Caliptra
//! VDM commands. The protocol/dispatch/framing all live in the
//! `caliptra-mcu-spdm-vdm-handler` lib; this hook only supplies the device ops.

extern crate alloc;

use crate::auth_keys::{TEST_AUTH_ECC_PUB_KEY_X, TEST_AUTH_ECC_PUB_KEY_Y, TEST_AUTH_MLDSA_PUB_KEY};
use alloc::boxed::Box;
use caliptra_mcu_common_commands::{
    CaliptraCompletionCode as CommonCompletionCode, GetLogResult, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError, PayloadStream};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_mbox_common::messages::HybridSignature;
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCommands, CaliptraVdmLogResult, CaliptraVdmResult,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{
    get_attested_csr_ecc384, get_attested_csr_mldsa87, request_debug_unlock_challenge,
    rng_generate, ApiAlloc, McuErrorCode, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};

/// AsymAlgo wire encoding (`EccP384 = 1`, `MlDsa87 = 2`), mirrored locally so
/// the hook does not depend on caliptra-api.
const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

/// HMAC command ID used by the host for the FE_PROG authorized sub-command.
const FE_PROG_CMD_ID: u32 = 0x4D43_4650;

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
        sig: &HybridSignature,
        scratch: &A,
    ) -> CaliptraVdmResult<()> {
        verify_fe_prog_signatures(partition, sig).await?;
        crate::caliptra_cmd_handler::device_ops::program_field_entropy(scratch, partition)
            .await
            .map_err(map_common_completion)
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

fn copy_bytes(src: &[u8], out: &mut [u8]) -> CaliptraVdmResult<usize> {
    if src.len() > out.len() {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }
    for (d, s) in out.iter_mut().zip(src) {
        *d = *s;
    }
    Ok(src.len())
}

async fn verify_fe_prog_signatures(partition: u32, sig: &HybridSignature) -> CaliptraVdmResult<()> {
    let challenge = AUTH_CHALLENGE
        .lock()
        .await
        .take()
        .ok_or(CaliptraCompletionCode::AccessDenied)?;
    let partition_bytes = partition.to_le_bytes();

    crate::caliptra_cmd_handler::device_ops::verify_authorized_signatures(
        FE_PROG_CMD_ID,
        &partition_bytes,
        &challenge,
        TEST_AUTH_ECC_PUB_KEY_X,
        TEST_AUTH_ECC_PUB_KEY_Y,
        TEST_AUTH_MLDSA_PUB_KEY,
        sig,
    )
    .await
    .map_err(map_common_completion)
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
