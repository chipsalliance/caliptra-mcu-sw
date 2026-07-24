// Licensed under the Apache-2.0 license

pub(crate) mod debug_log;
pub(crate) mod device_ops;

use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DebugUnlockChallenge,
    DeviceCapabilities, FirmwareVersion, GetLogResult, LogType, MAX_FW_VERSION_LEN,
};
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libapi_caliptra::ocp_lock::{
    HpkeHandle, OcpLock, OcpLockEnumerateHpkeHandlesResp,
};
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libapi_caliptra::signer::CaliptraDpeSigner;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_mbox_common::config;
use mcu_caliptra_api_lite::ApiAlloc;

pub struct CaliptraCmdBackend;

impl CaliptraCmdHandler for CaliptraCmdBackend {
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()> {
        let bytes = config::TEST_FIRMWARE_VERSIONS
            .get(index as usize)
            .ok_or(CaliptraCompletionCode::InvalidParameter)?
            .as_bytes();
        if bytes.len() > MAX_FW_VERSION_LEN {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        version.ver_str[..bytes.len()].copy_from_slice(bytes);
        version.len = bytes.len();
        Ok(())
    }

    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()> {
        let caps = &config::TEST_DEVICE_CAPABILITIES;
        capabilities.caliptra_rt = caps.caliptra_rt;
        capabilities.caliptra_fmc = caps.caliptra_fmc;
        capabilities.caliptra_rom = caps.caliptra_rom;
        capabilities.mcu_rt = caps.mcu_rt;
        capabilities.mcu_rom = caps.mcu_rom;
        capabilities.reserved = caps.reserved;
        Ok(())
    }

    async fn export_attested_csr<Alloc: ApiAlloc>(
        &self,
        _alloc: &Alloc,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        device_ops::export_attested_csr(device_key_id, algorithm, nonce, csr_buf).await
    }

    async fn export_idevid_csr<Alloc: ApiAlloc>(
        &self,
        _alloc: &Alloc,
        algorithm: u32,
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        device_ops::export_idevid_csr(algorithm, csr_buf).await
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

    async fn program_field_entropy<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        partition: u32,
    ) -> CaliptraCmdResult<()> {
        device_ops::program_field_entropy(alloc, partition).await
    }

    async fn request_debug_unlock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        unlock_level: u8,
        challenge: &mut DebugUnlockChallenge,
    ) -> CaliptraCmdResult<()> {
        let mut out = [0u8; caliptra_mcu_common_commands::DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE
            + caliptra_mcu_common_commands::DEBUG_UNLOCK_CHALLENGE_SIZE];
        let len = device_ops::request_debug_unlock(alloc, unlock_level, &mut out).await?;
        if len != out.len() {
            return Err(CaliptraCompletionCode::OperationFailed);
        }
        challenge.unique_device_identifier.copy_from_slice(
            &out[..caliptra_mcu_common_commands::DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
        );
        challenge.challenge.copy_from_slice(
            &out[caliptra_mcu_common_commands::DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE..],
        );
        Ok(())
    }

    async fn authorize_debug_unlock_token<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        token_request: &[u8],
    ) -> CaliptraCmdResult<()> {
        // Pass-through: the requester sends a complete Caliptra request
        // (including the mailbox checksum header), identical to the VDM path.
        device_ops::authorize_debug_unlock_token(alloc, token_request).await
    }

    #[cfg(feature = "ocp-lock")]
    async fn get_ocp_lock_endorsement_cert(
        &self,
        hpke_handle: &HpkeHandle,
        cert_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let mailbox = Mailbox::new();
        let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::APP_RUNTIME_CONFIG);
        let signer = CaliptraDpeSigner::new(&mailbox);

        ocp_lock
            .get_hpke_public_key_x509(hpke_handle, cert_buf, &signer)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                CaliptraApiError::BufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
                _ => CaliptraCompletionCode::OperationFailed,
            })
    }

    #[cfg(feature = "ocp-lock")]
    async fn ocp_lock_enumerate_hpke_handles(
        &self,
        resp: &mut OcpLockEnumerateHpkeHandlesResp,
    ) -> CaliptraCmdResult<()> {
        let mailbox = Mailbox::new();
        let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::APP_RUNTIME_CONFIG);

        ocp_lock
            .enumerate_hpke_handles(resp)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                _ => CaliptraCompletionCode::OperationFailed,
            })
    }

    #[cfg(feature = "ocp-lock")]
    async fn get_ocp_lock_epoch_key_report(
        &self,
        nonce: &[u8; 32],
        sek_state: caliptra_mcu_mbox_common::messages::SekState,
        report_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let mailbox = Mailbox::new();
        let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::APP_RUNTIME_CONFIG);
        let signer = CaliptraDpeSigner::new(&mailbox);

        let len = ocp_lock
            .get_ocp_lock_epoch_key_report(nonce, sek_state, &signer, report_buf)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                CaliptraApiError::BufferTooSmall | CaliptraApiError::InvalidArgBufferTooSmall => {
                    CaliptraCompletionCode::CaliptraBufferTooSmall
                }
                _ => CaliptraCompletionCode::OperationFailed,
            })?;

        Ok(len)
    }
}
