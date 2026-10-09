// Licensed under the Apache-2.0 license

//! Platform hooks for Caliptra SPDM VDM streaming.

use caliptra_mcu_common_commands::CaliptraCompletionCode as CommonCode;
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_spdm_traits::{
    McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};
use caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdm, CaliptraVdmResult, CaliptraVdmStreamOps,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api::{
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};

use crate::caliptra_cmd_handler::CaliptraCmdBackend;
use crate::mcu_mbox::cmd_auth_mock;

static DEBUG_UNLOCK_TOKEN_STREAM: Mutex<CriticalSectionRawMutex, bool> = Mutex::new(false);

pub struct CaliptraVdmStreamHook;

type EnabledVdm = CaliptraVdm<
    'static,
    CaliptraCmdBackend,
    CaliptraVdmStreamHook,
    cmd_auth_mock::MockCommandAuthorizer,
>;

pub struct AppVdmBackend(Option<EnabledVdm>);

impl AppVdmBackend {
    pub fn enabled(
        commands: &'static CaliptraCmdBackend,
        stream: &'static CaliptraVdmStreamHook,
        authorization: &'static cmd_auth_mock::MockCommandAuthorizer,
    ) -> Self {
        Self(Some(CaliptraVdm::new(commands, stream, authorization)))
    }

    pub const fn disabled() -> Self {
        Self(None)
    }
}

impl SpdmVdmBackend for AppVdmBackend {
    const USES_LARGE_RESPONSE: bool = EnabledVdm::USES_LARGE_RESPONSE;
    const LARGE_RESPONSE_CAPACITY: usize = EnabledVdm::LARGE_RESPONSE_CAPACITY;

    fn large_response_capacity(&self, req: &[u8]) -> usize {
        self.0
            .as_ref()
            .map_or(0, |backend| backend.large_response_capacity(req))
    }

    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        self.0
            .as_ref()
            .is_some_and(|backend| backend.match_id(registry))
    }

    async fn start_authorize_debug_unlock_token_stream<Alloc, Io>(
        &self,
        req_len: usize,
        first: &[u8],
        alloc: &Alloc,
        io: &Io,
    ) -> McuResult<bool>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        match &self.0 {
            Some(backend) => {
                backend
                    .start_authorize_debug_unlock_token_stream(req_len, first, alloc, io)
                    .await
            }
            None => Ok(false),
        }
    }

    async fn continue_authorize_debug_unlock_token_stream<Alloc, Io>(
        &self,
        chunk: &[u8],
        alloc: &Alloc,
        io: &Io,
    ) -> McuResult<()>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        match &self.0 {
            Some(backend) => {
                backend
                    .continue_authorize_debug_unlock_token_stream(chunk, alloc, io)
                    .await
            }
            None => Err(mcu_error::codes::NOT_IMPLEMENTED),
        }
    }

    async fn finish_authorize_debug_unlock_token_stream<Alloc, Io>(
        &self,
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        match &self.0 {
            Some(backend) => {
                backend
                    .finish_authorize_debug_unlock_token_stream(rsp)
                    .await
            }
            None => Err(mcu_error::codes::NOT_IMPLEMENTED),
        }
    }

    async fn abort_authorize_debug_unlock_token_stream<Alloc, Io>(&self, alloc: &Alloc, io: &Io)
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        if let Some(backend) = &self.0 {
            backend
                .abort_authorize_debug_unlock_token_stream(alloc, io)
                .await;
        }
    }

    fn handle_request<Alloc, Io>(
        &self,
        req: &[u8],
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> impl core::future::Future<Output = McuResult<VdmResponse>>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        self.0.as_ref().unwrap().handle_request(req, rsp)
    }
}

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
            if let Err(error) = mailbox.send_chunk(first).await {
                let _ = mailbox.abort_chunked_request().await;
                *active = false;
                return Err(map_mailbox_error(error));
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
        if let Err(error) = mailbox.send_chunk(chunk).await {
            let _ = mailbox.abort_chunked_request().await;
            *active = false;
            return Err(map_mailbox_error(error));
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
        let mut response = [0u8; PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN];
        let result = mailbox
            .execute_chunked_request(PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, &mut response)
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
