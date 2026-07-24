// Licensed under the Apache-2.0 license

//! Platform hooks for Caliptra SPDM VDM streaming and authorization.

use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCompletionCode as CommonCode, CommandAuthorizer,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_mbox_common::messages::HybridSignature;
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmAuthorization, CaliptraVdmResult, CaliptraVdmStreamOps,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};

use crate::caliptra_cmd_handler::CaliptraCmdBackend;
use crate::mcu_mbox::cmd_auth_mock;

/// MC_FE_PROG sub-command (`MCFP`).
const FE_PROG_CMD_ID: u32 = 0x4D43_4650;

// Kernel chunked-mailbox state rejects other processes; this flag serializes this
// app's DebugUnlock stream and lets abort clean up the in-flight mailbox request.
static DEBUG_UNLOCK_TOKEN_STREAM: Mutex<CriticalSectionRawMutex, bool> = Mutex::new(false);

pub struct CaliptraVdmStreamHook;
pub struct CaliptraVdmAuthorizationHook;

impl CaliptraVdmStreamOps for CaliptraVdmStreamHook {
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
        let mut resp = [0u8; PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN];
        let result = mailbox
            .execute_chunked_request(PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, &mut resp)
            .await
            .map_err(map_mailbox_error);
        *active = false;
        result.map(|_| ())
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
}

impl CaliptraVdmAuthorization for CaliptraVdmAuthorizationHook {
    async fn get_auth_challenge<A: SpdmPalAlloc>(
        &self,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let challenge = crate::caliptra_cmd_handler::device_ops::generate_auth_challenge(scratch)
            .await
            .map_err(map_common_completion)?;
        let mut authorizer = cmd_auth_mock::MockCommandAuthorizer;
        authorizer.set_challenge(challenge);
        out.get_mut(..challenge.len())
            .ok_or(CaliptraCompletionCode::InsufficientResources)?
            .copy_from_slice(&challenge);
        Ok(challenge.len())
    }

    async fn program_field_entropy<A: SpdmPalAlloc>(
        &self,
        partition: u32,
        sig: &HybridSignature,
        scratch: &A,
    ) -> CaliptraVdmResult<()> {
        let mut authorizer = cmd_auth_mock::MockCommandAuthorizer;
        authorizer
            .verify_signatures(FE_PROG_CMD_ID, &partition.to_le_bytes(), sig)
            .await
            .map_err(|_| CaliptraCompletionCode::AccessDenied)?;
        CaliptraCmdBackend
            .program_field_entropy(scratch, partition)
            .await
            .map_err(map_common_completion)
    }
}

fn map_mailbox_error(error: MailboxError) -> CaliptraCompletionCode {
    map_common_completion(crate::caliptra_cmd_handler::device_ops::map_mailbox_error(
        error,
    ))
}

fn map_common_completion(code: CommonCode) -> CaliptraCompletionCode {
    match code {
        CommonCode::Success => CaliptraCompletionCode::Success,
        CommonCode::GeneralError => CaliptraCompletionCode::GeneralError,
        CommonCode::InvalidParameter => CaliptraCompletionCode::InvalidParameter,
        CommonCode::InvalidLength => CaliptraCompletionCode::InvalidLength,
        CommonCode::InvalidIdentifier => CaliptraCompletionCode::InvalidIdentifier,
        CommonCode::OperationFailed => CaliptraCompletionCode::OperationFailed,
        CommonCode::InsufficientResources => CaliptraCompletionCode::InsufficientResources,
        CommonCode::UnsupportedOperation => CaliptraCompletionCode::UnsupportedOperation,
        CommonCode::DeviceNotReady => CaliptraCompletionCode::DeviceNotReady,
        CommonCode::InvalidCommandVersion => CaliptraCompletionCode::InvalidCommandVersion,
        CommonCode::InvalidPayloadSize => CaliptraCompletionCode::InvalidPayloadSize,
        CommonCode::Timeout => CaliptraCompletionCode::Timeout,
        CommonCode::AccessDenied => CaliptraCompletionCode::AccessDenied,
        CommonCode::ResourceUnavailable => CaliptraCompletionCode::ResourceUnavailable,
        CommonCode::PolicyViolation => CaliptraCompletionCode::PolicyViolation,
        CommonCode::InvalidState => CaliptraCompletionCode::InvalidState,
        CommonCode::CaliptraMailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
        CommonCode::CaliptraBufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
    }
}
