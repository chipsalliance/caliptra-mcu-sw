// Licensed under the Apache-2.0 license

extern crate alloc;

mod debug_log;

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

        execute_mailbox_cmd(
            &mailbox,
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.0,
            req.as_mut_bytes(),
            &mut resp_buf,
        )
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

        let resp = ProductionAuthDebugUnlockChallenge::ref_from_bytes(&resp_buf)
            .map_err(|_| CaliptraCompletionCode::GeneralError)?;

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

/// Small remainder buffer for streaming — holds up to 3 bytes that couldn't be
/// sent because the mailbox FIFO requires 4-byte-aligned writes.
static STREAM_REMAINDER: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    StreamRemainder,
> = embassy_sync::mutex::Mutex::new(StreamRemainder {
    buf: [0; 3],
    len: 0,
});

struct StreamRemainder {
    buf: [u8; 3],
    len: usize,
}

/// Send data to the mailbox in 4-byte-aligned sub-chunks, holding any
/// remainder (< 4 bytes) in STREAM_REMAINDER for the next call.
async fn send_aligned(
    mailbox: &caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox<
        caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
    >,
    data: &[u8],
) -> Result<(), caliptra_mcu_spdm_lib::vdm_handler::VdmError> {
    use caliptra_mcu_spdm_lib::vdm_handler::VdmError;

    let mut remainder = STREAM_REMAINDER.lock().await;
    // Build a working buffer: remainder from last call + new data
    // We process in 256-byte sub-chunks max
    const SUB_CHUNK: usize = 256;
    let mut buf = [0u8; SUB_CHUNK + 4]; // extra room for remainder prefix
    let mut offset = 0usize;

    // Prepend any leftover bytes from previous call
    let rem_len = remainder.len;
    if rem_len > 0 {
        buf[..rem_len].copy_from_slice(&remainder.buf[..rem_len]);
        remainder.len = 0;
    }

    let total = rem_len + data.len();
    let mut src_offset = 0usize;

    while offset < total {
        // Fill buf starting after any remainder already placed
        let buf_start = if offset == 0 { rem_len } else { 0 };
        let remaining_data = data.len() - src_offset;
        let can_fill = SUB_CHUNK.min(buf_start + remaining_data) - buf_start;
        buf[buf_start..buf_start + can_fill]
            .copy_from_slice(&data[src_offset..src_offset + can_fill]);
        src_offset += can_fill;
        let available = buf_start + can_fill;

        // Round down to 4-byte boundary
        let send_len = available & !3;
        let leftover = available - send_len;

        if send_len > 0 {
            mailbox
                .send_chunk(&buf[..send_len])
                .await
                .map_err(|_| VdmError::StreamError)?;
        }

        // Save leftover for next iteration or next call
        if leftover > 0 {
            let mut new_buf = [0u8; 3];
            new_buf[..leftover].copy_from_slice(&buf[send_len..send_len + leftover]);
            if src_offset >= data.len() {
                // No more data — save remainder for next call
                remainder.buf[..leftover].copy_from_slice(&new_buf[..leftover]);
                remainder.len = leftover;
                break;
            } else {
                // More data to process — move leftover to start of buf
                buf[..leftover].copy_from_slice(&new_buf[..leftover]);
                // Continue filling from buf[leftover..]
                offset += send_len;
                // Set buf_start for next iteration — handled by the else branch above
                continue;
            }
        }

        offset += send_len;
    }

    Ok(())
}

/// Flush any remaining bytes in the stream remainder buffer (padded to 4 bytes).
async fn flush_remainder(
    mailbox: &caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox<
        caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
    >,
) -> Result<(), caliptra_mcu_spdm_lib::vdm_handler::VdmError> {
    use caliptra_mcu_spdm_lib::vdm_handler::VdmError;

    let mut remainder = STREAM_REMAINDER.lock().await;
    if remainder.len > 0 {
        let actual_len = remainder.len;
        let mut buf = [0u8; 4];
        buf[..actual_len].copy_from_slice(&remainder.buf[..actual_len]);
        remainder.len = 0;
        mailbox
            .send_chunk(&buf)
            .await
            .map_err(|_| VdmError::StreamError)?;
    }
    Ok(())
}

#[async_trait]
impl caliptra_mcu_spdm_lib::vdm_handler::VdmStreamHandler for CaliptraCmdBackend {
    fn stream_supported(&self, vdm_command_code: u8) -> Option<u32> {
        use caliptra_api::mailbox::CommandId;
        match vdm_command_code {
            // AuthorizeDebugUnlockToken (0x0B)
            0x0B => Some(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.0),
            // RequestDebugUnlock (0x0A) — small enough for normal buffered path
            _ => None,
        }
    }

    async fn stream_init(
        &self,
        mailbox_cmd: u32,
        total_payload_len: usize,
        first_chunk_payload: &[u8],
    ) -> caliptra_mcu_spdm_lib::vdm_handler::VdmResult<()> {
        use caliptra_mcu_spdm_lib::vdm_handler::VdmError;

        let mailbox = caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox::<
            caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
        >::new();

        // Clear any stale remainder
        {
            let mut remainder = STREAM_REMAINDER.lock().await;
            remainder.len = 0;
        }

        mailbox
            .start_chunked_request(mailbox_cmd, total_payload_len)
            .await
            .map_err(|_| VdmError::StreamError)?;

        // Send first chunk payload through aligned sender
        send_aligned(&mailbox, first_chunk_payload).await?;

        Ok(())
    }

    async fn stream_chunk(
        &self,
        chunk_data: &[u8],
    ) -> caliptra_mcu_spdm_lib::vdm_handler::VdmResult<()> {
        let mailbox = caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox::<
            caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
        >::new();
        send_aligned(&mailbox, chunk_data).await
    }

    async fn stream_finish(
        &self,
        mailbox_cmd: u32,
        rsp_buf: &mut [u8],
    ) -> caliptra_mcu_spdm_lib::vdm_handler::VdmResult<usize> {
        use caliptra_mcu_spdm_lib::vdm_handler::VdmError;

        let mailbox = caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox::<
            caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
        >::new();

        // Flush any remaining bytes (padded to 4-byte boundary)
        flush_remainder(&mailbox).await?;

        let resp_len = mailbox
            .execute_chunked_request(mailbox_cmd, rsp_buf)
            .await
            .map_err(|_| VdmError::StreamError)?;

        Ok(resp_len)
    }

    async fn stream_abort(&self) {
        // Clear remainder state
        let mut remainder = STREAM_REMAINDER.lock().await;
        remainder.len = 0;
    }
}
