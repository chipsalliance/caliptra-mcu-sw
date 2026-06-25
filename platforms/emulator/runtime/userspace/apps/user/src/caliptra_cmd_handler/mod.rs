// Licensed under the Apache-2.0 license

extern crate alloc;

pub(crate) mod debug_log;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DebugUnlockChallenge,
    DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, GetLogResult, LogType,
};
use caliptra_mcu_libapi_caliptra::certificate::{CertContext, IDEV_ECC_CSR_MAX_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;

pub struct CaliptraCmdBackend;

#[async_trait]
impl CaliptraCmdHandler for CaliptraCmdBackend {
    async fn get_firmware_version(
        &self,
        _index: u32,
        _version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn get_device_id(&self, _device_id: &mut DeviceId) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn get_device_info(&self, _index: u32, _info: &mut DeviceInfo) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn get_device_capabilities(
        &self,
        _capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn export_attested_csr(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let algo =
            AsymAlgo::try_from_u32(algorithm).ok_or(CaliptraCompletionCode::InvalidParameter)?;

        let mut cert_ctx = CertContext::new();

        let len = cert_ctx
            .get_attested_csr(algo, device_key_id, nonce, csr_buf)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                CaliptraApiError::BufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
                CaliptraApiError::InvalidResponse
                | CaliptraApiError::Mailbox(_)
                | CaliptraApiError::Syscall(_) => CaliptraCompletionCode::OperationFailed,
                // Any other variant is not produced by get_attested_csr's call
                // chain today. Reaching here means a deeper call started
                // returning an unanticipated variant — surface it loudly.
                _ => CaliptraCompletionCode::GeneralError,
            })?;

        Ok(len)
    }

    async fn export_idevid_csr(
        &self,
        algorithm: u32,
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let algo =
            AsymAlgo::try_from_u32(algorithm).ok_or(CaliptraCompletionCode::InvalidParameter)?;

        let mut cert_ctx = CertContext::new();

        match algo {
            AsymAlgo::EccP384 => {
                let mut csr_der = [0u8; IDEV_ECC_CSR_MAX_SIZE];
                let len = cert_ctx
                    .get_idev_csr(&mut csr_der)
                    .await
                    .map_err(|e| match e {
                        CaliptraApiError::MailboxBusy => {
                            CaliptraCompletionCode::CaliptraMailboxBusy
                        }
                        CaliptraApiError::UnprovisionedCsr => CaliptraCompletionCode::InvalidState,
                        CaliptraApiError::InvalidResponse
                        | CaliptraApiError::Mailbox(_)
                        | CaliptraApiError::Syscall(_) => CaliptraCompletionCode::OperationFailed,
                        // Any other variant is not produced by get_idev_csr's
                        // call chain today; surface it as GeneralError.
                        _ => CaliptraCompletionCode::GeneralError,
                    })?;
                if len > csr_buf.len() {
                    return Err(CaliptraCompletionCode::CaliptraBufferTooSmall);
                }
                csr_buf[..len].copy_from_slice(&csr_der[..len]);
                Ok(len)
            }
            AsymAlgo::MlDsa87 => {
                // MLDSA IDevID CSR not yet supported at the mailbox level
                Err(CaliptraCompletionCode::UnsupportedOperation)
            }
        }
    }

    /// Drain entries of `log_type` from the backing store.
    ///
    /// `LogType::Debug` is backed by the Tock logging-flash capsule via
    /// [`LoggingSyscall`](caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall);
    /// the kernel cursor is advanced as entries are consumed and any entry
    /// that does not fit is held over for the next call.
    ///
    /// `LogType::Attestation` returns `UnsupportedOperation` until the
    /// Caliptra-mailbox-backed implementation lands.
    async fn get_log(&self, log_type: u32, data: &mut [u8]) -> CaliptraCmdResult<GetLogResult> {
        match LogType::try_from(log_type)? {
            LogType::Debug => debug_log::drain(data).await,
            LogType::Attestation => Err(CaliptraCompletionCode::UnsupportedOperation),
        }
    }

    /// Erase the log of `log_type` and reset the read cursor.
    async fn clear_log(&self, log_type: u32) -> CaliptraCmdResult<()> {
        match LogType::try_from(log_type)? {
            LogType::Debug => debug_log::clear().await,
            LogType::Attestation => Err(CaliptraCompletionCode::UnsupportedOperation),
        }
    }

    async fn program_field_entropy(&self, partition: u32) -> CaliptraCmdResult<()> {
        use caliptra_api::mailbox::{CommandId, FeProgReq};
        use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
        use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
        use zerocopy::IntoBytes;

        let mailbox = Mailbox::new();
        let mut req = FeProgReq {
            partition,
            ..Default::default()
        };

        let mut resp_buf = [0u8; 8];
        execute_mailbox_cmd(
            &mailbox,
            CommandId::FE_PROG.0,
            req.as_mut_bytes(),
            &mut resp_buf,
        )
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

        Ok(())
    }

    async fn request_debug_unlock(
        &self,
        unlock_level: u8,
        challenge: &mut DebugUnlockChallenge,
    ) -> CaliptraCmdResult<()> {
        use caliptra_api::mailbox::{
            CommandId, MailboxReqHeader, ProductionAuthDebugUnlockChallenge,
            ProductionAuthDebugUnlockReq,
        };
        use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
        use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
        use zerocopy::{FromBytes, IntoBytes};

        let mailbox = Mailbox::new();
        let mut req = ProductionAuthDebugUnlockReq {
            hdr: MailboxReqHeader::default(),
            length: 2,
            unlock_level,
            reserved: [0; 3],
        };

        let mut resp_buf = [0u8; core::mem::size_of::<ProductionAuthDebugUnlockChallenge>()];

        let resp_len = execute_mailbox_cmd(
            &mailbox,
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.0,
            req.as_mut_bytes(),
            &mut resp_buf,
        )
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
        if resp_len != core::mem::size_of::<ProductionAuthDebugUnlockChallenge>() {
            return Err(CaliptraCompletionCode::OperationFailed);
        }

        let resp = ProductionAuthDebugUnlockChallenge::ref_from_bytes(&resp_buf)
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

        challenge
            .unique_device_identifier
            .copy_from_slice(&resp.unique_device_identifier);
        challenge.challenge.copy_from_slice(&resp.challenge);

        Ok(())
    }

    async fn authorize_debug_unlock_token(&self, token_data: &[u8]) -> CaliptraCmdResult<()> {
        use alloc::vec;
        use caliptra_api::mailbox::{CommandId, MailboxReqHeader, MailboxRespHeader};
        use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
        use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;

        let mailbox = Mailbox::new();

        // Build full request: MailboxReqHeader (zeroed, checksum computed by execute_mailbox_cmd) + token_data
        let hdr_len = core::mem::size_of::<MailboxReqHeader>();
        let mut req = vec![0u8; hdr_len + token_data.len()];
        req[hdr_len..].copy_from_slice(token_data);

        let mut resp_buf = [0u8; core::mem::size_of::<MailboxRespHeader>()];

        execute_mailbox_cmd(
            &mailbox,
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.0,
            &mut req,
            &mut resp_buf,
        )
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

        Ok(())
    }
}
