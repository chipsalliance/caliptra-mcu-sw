// Licensed under the Apache-2.0 license

//! Platform implementation of the Caliptra VDM device-operations hook.
//!
//! [`CaliptraVdmHook`] is the emulator's [`CaliptraVdmCommands`] backend: it
//! performs the actual device work (Caliptra mailbox calls) for the Caliptra
//! VDM commands. The protocol/dispatch/framing all live in the
//! `caliptra-mcu-spdm-vdm-handler` lib; this hook only supplies the device ops.

use caliptra_mcu_common_commands::{
    CaliptraCompletionCode as CommonCompletionCode, GetLogResult, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCommands, CaliptraVdmLogResult, CaliptraVdmResult,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};

/// HMAC command ID used by the host for the FE_PROG authorized sub-command.
const FE_PROG_CMD_ID: u32 = 0x4D43_4650;

static AUTH_CHALLENGE: Mutex<CriticalSectionRawMutex, Option<[u8; 32]>> = Mutex::new(None);
// Kernel chunked-mailbox state rejects other processes; this flag serializes this
// app's DebugUnlock stream and lets abort clean up the in-flight mailbox request.
static DEBUG_UNLOCK_TOKEN_STREAM: Mutex<CriticalSectionRawMutex, bool> = Mutex::new(false);

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

        crate::caliptra_cmd_handler::device_ops::request_debug_unlock(scratch, unlock_level, out)
            .await
            .map_err(map_common_completion)
    }

    async fn authorize_debug_unlock_token<A: SpdmPalAlloc>(
        &self,
        token_data: &[u8],
        scratch: &A,
    ) -> CaliptraVdmResult<()> {
        // The host sends AuthorizeDebugUnlockToken as a complete Caliptra RT
        // mailbox request, including MailboxReqHeader.checksum. Preserve those
        // payload bytes exactly; do not synthesize another mailbox header here.
        crate::caliptra_cmd_handler::device_ops::authorize_debug_unlock_token(scratch, token_data)
            .await
            .map_err(map_common_completion)
    }

    async fn start_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(
        &self,
        token_len: usize,
        first: &[u8],
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        let mut active = DEBUG_UNLOCK_TOKEN_STREAM.lock().await;
        let mailbox = Mailbox::<DefaultSyscalls>::new();
        if *active {
            let _ = mailbox.abort_chunked_request().await;
            *active = false;
        }

        mailbox
            .start_chunked_request(PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, token_len)
            .await
            .map_err(map_mailbox_error)?;
        *active = true;
        if !first.is_empty() {
            if let Err(err) = mailbox.send_chunk(first).await {
                let _ = mailbox.abort_chunked_request().await;
                *active = false;
                return Err(map_mailbox_error(err));
            }
        }
        Ok(())
    }

    async fn continue_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(
        &self,
        chunk: &[u8],
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let mut active = DEBUG_UNLOCK_TOKEN_STREAM.lock().await;
        if !*active {
            return Err(CaliptraCompletionCode::InvalidState);
        }
        let mailbox = Mailbox::<DefaultSyscalls>::new();
        if let Err(err) = mailbox.send_chunk(chunk).await {
            let _ = mailbox.abort_chunked_request().await;
            *active = false;
            return Err(map_mailbox_error(err));
        }
        Ok(())
    }

    async fn finish_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(
        &self,
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        let mut active = DEBUG_UNLOCK_TOKEN_STREAM.lock().await;
        if !*active {
            return Err(CaliptraCompletionCode::InvalidState);
        }
        let mailbox = Mailbox::<DefaultSyscalls>::new();
        // 8-byte response header is a write-only throwaway; a stack buffer avoids
        // the scratch alloc and its failure/cleanup path for a fixed tiny size.
        let mut resp_buf = [0u8; PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN];
        let result = mailbox
            .execute_chunked_request(PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, &mut resp_buf)
            .await
            .map_err(|e| {
                map_common_completion(crate::caliptra_cmd_handler::device_ops::map_mailbox_error(
                    e,
                ))
            });
        *active = false;
        result?;
        Ok(())
    }

    async fn abort_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(&self, _scratch: &A) {
        let mut active = DEBUG_UNLOCK_TOKEN_STREAM.lock().await;
        if *active {
            let _ = Mailbox::<DefaultSyscalls>::new()
                .abort_chunked_request()
                .await;
            *active = false;
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
        crate::caliptra_cmd_handler::device_ops::export_attested_csr(
            device_key_id,
            algorithm,
            nonce,
            out,
        )
        .await
        .map_err(map_common_completion)
    }

    async fn get_auth_challenge<A: SpdmPalAlloc>(
        &self,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let challenge = crate::caliptra_cmd_handler::device_ops::generate_auth_challenge(scratch)
            .await
            .map_err(map_common_completion)?;
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
        crate::caliptra_cmd_handler::device_ops::program_field_entropy(scratch, partition)
            .await
            .map_err(map_common_completion)
    }
}

fn map_mailbox_error(e: MailboxError) -> CaliptraCompletionCode {
    map_common_completion(crate::caliptra_cmd_handler::device_ops::map_mailbox_error(
        e,
    ))
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

async fn verify_fe_prog_mac<A: mcu_caliptra_api_lite::ApiAlloc>(
    scratch: &A,
    partition: u32,
    mac: &[u8; 48],
) -> CaliptraVdmResult<()> {
    let challenge = AUTH_CHALLENGE
        .lock()
        .await
        .take()
        .ok_or(CaliptraCompletionCode::AccessDenied)?;
    let partition_bytes = partition.to_le_bytes();

    crate::caliptra_cmd_handler::device_ops::verify_authorized_mac(
        scratch,
        &crate::caliptra_cmd_handler::device_ops::TEST_AUTH_CMD_HMAC_KEY,
        FE_PROG_CMD_ID,
        &partition_bytes,
        &challenge,
        mac,
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
