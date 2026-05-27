// Licensed under the Apache-2.0 license

extern crate alloc;

mod debug_log;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DebugUnlockChallenge,
    DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, GetLogResult, LogType, Uid,
    MAX_FW_VERSION_LEN, MAX_UID_LEN,
};
use caliptra_mcu_libapi_caliptra::certificate::{CertContext, IDEV_ECC_CSR_MAX_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;
use caliptra_mcu_mbox_common::config;
use mcu_spdm_lite_stack::{SpdmVdmBackend, StandardsBodyId, VdmRequest};
use zerocopy::IntoBytes;

pub struct CaliptraCmdBackend;

/// Size-conscious spdm-lite OCP Caliptra VDM backend.
///
/// This backend uses static dispatch through `SpdmVdmBackend`; it does not use
/// `async_trait`, boxed futures, or a `dyn CaliptraCmdHandler` path.
pub struct CaliptraOcpVdm;

const OCP_VENDOR_ID: u32 = 42623;
const CALIPTRA_VDM_COMMAND_VERSION: u8 = 0x01;

impl CaliptraOcpVdm {
    fn write_completion(
        rsp: &mut [u8],
        command: u8,
        completion: CaliptraCompletionCode,
    ) -> Result<usize, mcu_spdm_lite_stack::SpdmError> {
        let out = rsp
            .get_mut(..3)
            .ok_or(mcu_spdm_lite_stack::SPDM_UNSPECIFIED)?;
        out[0] = CALIPTRA_VDM_COMMAND_VERSION;
        out[1] = command;
        out[2] = completion as u8;
        Ok(3)
    }

    fn write_bytes(
        rsp: &mut [u8],
        offset: usize,
        bytes: &[u8],
    ) -> Result<usize, mcu_spdm_lite_stack::SpdmError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(mcu_spdm_lite_stack::SPDM_UNSPECIFIED)?;
        rsp.get_mut(offset..end)
            .ok_or(mcu_spdm_lite_stack::SPDM_UNSPECIFIED)?
            .copy_from_slice(bytes);
        Ok(end)
    }

    fn write_u16(
        rsp: &mut [u8],
        offset: usize,
        value: u16,
    ) -> Result<usize, mcu_spdm_lite_stack::SpdmError> {
        Self::write_bytes(rsp, offset, &value.to_le_bytes())
    }

    fn write_success(rsp: &mut [u8], command: u8) -> Result<usize, mcu_spdm_lite_stack::SpdmError> {
        Self::write_completion(rsp, command, CaliptraCompletionCode::Success)
    }

    fn read_u32(payload: &[u8]) -> Result<u32, mcu_spdm_lite_stack::SpdmError> {
        if payload.len() != 4 {
            return Err(mcu_spdm_lite_stack::SPDM_INVALID_REQUEST);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(payload);
        Ok(u32::from_le_bytes(bytes))
    }
}

impl SpdmVdmBackend for CaliptraOcpVdm {
    fn match_request(&self, req: &VdmRequest<'_>) -> bool {
        req.standard_id == StandardsBodyId::Iana && req.vendor_id == OCP_VENDOR_ID.to_le_bytes()
    }

    async fn handle_request(
        &self,
        req: VdmRequest<'_>,
        rsp: &mut [u8],
    ) -> mcu_spdm_lite_stack::SpdmResult<usize> {
        let Some((&command_version, rest)) = req.payload.split_first() else {
            return Err(mcu_spdm_lite_stack::SPDM_INVALID_REQUEST);
        };
        let Some((&command, payload)) = rest.split_first() else {
            return Err(mcu_spdm_lite_stack::SPDM_INVALID_REQUEST);
        };
        if command_version != CALIPTRA_VDM_COMMAND_VERSION {
            return Self::write_completion(
                rsp,
                command,
                CaliptraCompletionCode::InvalidCommandVersion,
            );
        }

        match command {
            0x01 => {
                let index = Self::read_u32(payload)?;
                let version_str = config::TEST_FIRMWARE_VERSIONS
                    .get(index as usize)
                    .ok_or(CaliptraCompletionCode::InvalidParameter);
                match version_str {
                    Ok(version_str) if version_str.len() <= MAX_FW_VERSION_LEN => {
                        let offset = Self::write_success(rsp, command)?;
                        Self::write_bytes(rsp, offset, version_str.as_bytes())
                    }
                    Ok(_) => Self::write_completion(
                        rsp,
                        command,
                        CaliptraCompletionCode::InvalidPayloadSize,
                    ),
                    Err(e) => Self::write_completion(rsp, command, e),
                }
            }
            0x02 => {
                if !payload.is_empty() {
                    return Err(mcu_spdm_lite_stack::SPDM_INVALID_REQUEST);
                }
                let caps = &config::TEST_DEVICE_CAPABILITIES;
                let mut out_caps = DeviceCapabilities::default();
                out_caps.caliptra_rt = caps.caliptra_rt;
                out_caps.caliptra_fmc = caps.caliptra_fmc;
                out_caps.caliptra_rom = caps.caliptra_rom;
                out_caps.mcu_rt = caps.mcu_rt;
                out_caps.mcu_rom = caps.mcu_rom;
                out_caps.reserved = caps.reserved;
                let offset = Self::write_success(rsp, command)?;
                Self::write_bytes(rsp, offset, out_caps.as_bytes())
            }
            0x03 => {
                if !payload.is_empty() {
                    return Err(mcu_spdm_lite_stack::SPDM_INVALID_REQUEST);
                }
                let device_id = &config::TEST_DEVICE_ID;
                let mut offset = Self::write_success(rsp, command)?;
                offset = Self::write_u16(rsp, offset, device_id.vendor_id)?;
                offset = Self::write_u16(rsp, offset, device_id.device_id)?;
                offset = Self::write_u16(rsp, offset, device_id.subsystem_vendor_id)?;
                Self::write_u16(rsp, offset, device_id.subsystem_id)
            }
            0x04 => {
                let index = Self::read_u32(payload)?;
                if index != 0 {
                    return Self::write_completion(
                        rsp,
                        command,
                        CaliptraCompletionCode::InvalidParameter,
                    );
                }
                let uid = &config::TEST_UID;
                if uid.len() > MAX_UID_LEN {
                    return Self::write_completion(
                        rsp,
                        command,
                        CaliptraCompletionCode::InvalidPayloadSize,
                    );
                }
                let offset = Self::write_success(rsp, command)?;
                Self::write_bytes(rsp, offset, uid)
            }
            0x05 | 0x06 | 0x07 | 0x08 | 0x0C | 0x0F => {
                Self::write_completion(rsp, command, CaliptraCompletionCode::UnsupportedOperation)
            }
            _ => Self::write_completion(rsp, command, CaliptraCompletionCode::UnsupportedOperation),
        }
    }
}

#[async_trait]
impl CaliptraCmdHandler for CaliptraCmdBackend {
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()> {
        let version_str = config::TEST_FIRMWARE_VERSIONS
            .get(index as usize)
            .ok_or(CaliptraCompletionCode::InvalidParameter)?;
        let bytes = version_str.as_bytes();
        if bytes.len() > MAX_FW_VERSION_LEN {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        version.ver_str[..bytes.len()].copy_from_slice(bytes);
        version.len = bytes.len();
        Ok(())
    }

    async fn get_device_id(&self, device_id: &mut DeviceId) -> CaliptraCmdResult<()> {
        let test_device_id = &config::TEST_DEVICE_ID;
        device_id.vendor_id = test_device_id.vendor_id;
        device_id.device_id = test_device_id.device_id;
        device_id.subsystem_vendor_id = test_device_id.subsystem_vendor_id;
        device_id.subsystem_id = test_device_id.subsystem_id;
        Ok(())
    }

    async fn get_device_info(&self, index: u32, info: &mut DeviceInfo) -> CaliptraCmdResult<()> {
        if index != 0 {
            return Err(CaliptraCompletionCode::InvalidParameter);
        }
        let test_uid = &config::TEST_UID;
        if test_uid.len() > MAX_UID_LEN {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        let mut unique_chip_id = [0u8; MAX_UID_LEN];
        unique_chip_id[..test_uid.len()].copy_from_slice(test_uid);
        *info = DeviceInfo::Uid(Uid {
            len: test_uid.len(),
            unique_chip_id,
        });
        Ok(())
    }

    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()> {
        let test_capabilities = &config::TEST_DEVICE_CAPABILITIES;
        capabilities.caliptra_rt = test_capabilities.caliptra_rt;
        capabilities.caliptra_fmc = test_capabilities.caliptra_fmc;
        capabilities.caliptra_rom = test_capabilities.caliptra_rom;
        capabilities.mcu_rt = test_capabilities.mcu_rt;
        capabilities.mcu_rom = test_capabilities.mcu_rom;
        capabilities.reserved = test_capabilities.reserved;
        Ok(())
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
