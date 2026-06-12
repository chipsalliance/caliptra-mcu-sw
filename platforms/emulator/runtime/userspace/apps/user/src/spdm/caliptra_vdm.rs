// Licensed under the Apache-2.0 license

//! Platform implementation of the Caliptra VDM device-operations hook.
//!
//! [`CaliptraVdmHook`] is the emulator's [`CaliptraVdmCommands`] backend: it
//! performs the actual device work (Caliptra mailbox calls) for the Caliptra
//! VDM commands. The protocol/dispatch/framing all live in the
//! `mcu-spdm-lite-vdm-handler` lib; this hook only supplies the device ops.

use arrayvec::ArrayVec;
use caliptra_mcu_common_commands::{
    CaliptraCompletionCode as CommonCompletionCode, DeviceCapabilities, DeviceId, GetLogResult,
    MAX_FW_VERSION_LEN, MAX_UID_LEN,
};
use caliptra_mcu_libapi_caliptra::certificate::{CertContext, IDEV_ECC_CSR_MAX_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::crypto::hmac::Hmac;
use caliptra_mcu_libapi_caliptra::crypto::import::{CmKeyUsage, Import};
use caliptra_mcu_libapi_caliptra::crypto::rng::Rng;
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use constant_time_eq::constant_time_eq;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{get_attested_csr_ecc384, get_attested_csr_mldsa87, McuErrorCode};
use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};
use mcu_spdm_lite_vdm_handler::iana::ocp::caliptra_vdm::{
    CaliptraCompletionCode, CaliptraVdmCommands, CaliptraVdmLogResult, CaliptraVdmResult,
};
use zerocopy::IntoBytes;

/// HMAC command ID used by the host for the FE_PROG authorized sub-command.
const FE_PROG_CMD_ID: u32 = 0x4D43_4650;
/// Symmetric test HMAC key used by the emulator validator path.
const TEST_AUTH_CMD_HMAC_KEY: [u8; 48] = [
    0x72, 0xec, 0x12, 0x02, 0x77, 0x69, 0xb9, 0xdc, 0x04, 0xbd, 0xd0, 0xc0, 0x86, 0xca, 0x1b, 0x20,
    0x2f, 0x47, 0x1e, 0xee, 0xf2, 0x8c, 0x2d, 0xa8, 0xc5, 0x4c, 0x75, 0xc2, 0x48, 0xa6, 0x80, 0x0a,
    0x11, 0xbf, 0xd5, 0xcd, 0x09, 0xed, 0x57, 0x0c, 0xb4, 0xc2, 0xa1, 0x37, 0x6b, 0xa2, 0xcb, 0xcd,
];

static AUTH_CHALLENGE: Mutex<CriticalSectionRawMutex, Option<[u8; 32]>> = Mutex::new(None);

/// AsymAlgo wire encoding mirrored from caliptra-api (`AsymAlgo::EccP384 = 1`,
/// `MlDsa87 = 2`); kept local so the hook does not pull in caliptra-api.
const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

/// Emulator Caliptra VDM device-operations backend.
pub struct CaliptraVdmHook;

impl CaliptraVdmCommands for CaliptraVdmHook {
    async fn firmware_version<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        area_index: u32,
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let Some(version) =
            caliptra_mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS.get(area_index as usize)
        else {
            return Err(CaliptraCompletionCode::InvalidParameter);
        };
        let bytes = version.as_bytes();
        if bytes.len() > MAX_FW_VERSION_LEN || bytes.len() > out.len() {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    async fn device_capabilities<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let test_capabilities = &caliptra_mcu_mbox_common::config::TEST_DEVICE_CAPABILITIES;
        let capabilities = DeviceCapabilities {
            caliptra_rt: test_capabilities.caliptra_rt,
            caliptra_fmc: test_capabilities.caliptra_fmc,
            caliptra_rom: test_capabilities.caliptra_rom,
            mcu_rt: test_capabilities.mcu_rt,
            mcu_rom: test_capabilities.mcu_rom,
            reserved: test_capabilities.reserved,
        };
        copy_bytes(capabilities.as_bytes(), out)
    }

    async fn device_id<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let test_device_id = &caliptra_mcu_mbox_common::config::TEST_DEVICE_ID;
        let device_id = DeviceId {
            vendor_id: test_device_id.vendor_id,
            device_id: test_device_id.device_id,
            subsystem_vendor_id: test_device_id.subsystem_vendor_id,
            subsystem_id: test_device_id.subsystem_id,
        };
        let mut offset = 0usize;
        copy_field(&device_id.vendor_id.to_le_bytes(), out, &mut offset)?;
        copy_field(&device_id.device_id.to_le_bytes(), out, &mut offset)?;
        copy_field(
            &device_id.subsystem_vendor_id.to_le_bytes(),
            out,
            &mut offset,
        )?;
        copy_field(&device_id.subsystem_id.to_le_bytes(), out, &mut offset)?;
        Ok(offset)
    }

    async fn device_info<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        info_index: u32,
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        if info_index != 0 {
            return Err(CaliptraCompletionCode::InvalidParameter);
        }
        let uid = &caliptra_mcu_mbox_common::config::TEST_UID;
        if uid.len() > MAX_UID_LEN {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        copy_bytes(uid, out)
    }

    async fn get_log<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        log_type: u32,
        _scratch: &A,
        _io: &I,
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

    async fn clear_log<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        log_type: u32,
        _scratch: &A,
        _io: &I,
    ) -> CaliptraVdmResult<()> {
        match log_type {
            0 => crate::caliptra_cmd_handler::debug_log::clear()
                .await
                .map_err(map_common_completion),
            1 => Err(CaliptraCompletionCode::UnsupportedOperation),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }

    async fn export_idevid_csr<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        algorithm: u32,
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let algo =
            AsymAlgo::try_from_u32(algorithm).ok_or(CaliptraCompletionCode::InvalidParameter)?;
        let mut cert_ctx = CertContext::new();
        match algo {
            AsymAlgo::EccP384 => {
                // The Caliptra mailbox API requires a full VarSizeDataResp-sized
                // IDevID CSR response buffer (~9 KiB), even though the CSR returned
                // by the emulator fixtures is much smaller. Do not reserve that from
                // the SPDM request scratch pool: the pool is intentionally sized for
                // SPDM-lite's steady-state work, while the VDM large-response buffer
                // already stages the bytes returned to the host.
                let mut csr_der = [0u8; IDEV_ECC_CSR_MAX_SIZE];
                let len = cert_ctx
                    .get_idev_csr(&mut csr_der)
                    .await
                    .map_err(map_idev_csr_error)?;
                if len > out.len() {
                    return Err(CaliptraCompletionCode::CaliptraBufferTooSmall);
                }
                out[..len].copy_from_slice(&csr_der[..len]);
                Ok(len)
            }
            AsymAlgo::MlDsa87 => Err(CaliptraCompletionCode::UnsupportedOperation),
        }
    }

    async fn export_attested_csr<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let result = match algorithm {
            ALGO_ECC_P384 => get_attested_csr_ecc384(device_key_id, nonce, out).await,
            ALGO_MLDSA87 => get_attested_csr_mldsa87(device_key_id, nonce, out).await,
            _ => return Err(CaliptraCompletionCode::InvalidParameter),
        };
        result.map_err(map_mcu_err)
    }

    async fn get_auth_challenge<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        _scratch: &A,
        _io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize> {
        let mut challenge = [0u8; 32];
        Rng::generate_random_number(&mut challenge)
            .await
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
        *AUTH_CHALLENGE.lock().await = Some(challenge);
        copy_bytes(&challenge, out)
    }

    async fn program_field_entropy<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        partition: u32,
        mac: &[u8; 48],
        _scratch: &A,
        _io: &I,
    ) -> CaliptraVdmResult<()> {
        use caliptra_api::mailbox::{CommandId, FeProgReq};

        verify_fe_prog_mac(partition, mac).await?;
        let mut req = FeProgReq {
            partition,
            ..Default::default()
        };
        let mut resp_buf = [0u8; 8];
        execute_mailbox_cmd(
            &Mailbox::new(),
            CommandId::FE_PROG.0,
            req.as_mut_bytes(),
            &mut resp_buf,
        )
        .await
        .map_err(map_caliptra_api_error)?;
        Ok(())
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
    out[..src.len()].copy_from_slice(src);
    Ok(src.len())
}

fn copy_field(src: &[u8], out: &mut [u8], offset: &mut usize) -> CaliptraVdmResult<()> {
    let end = offset
        .checked_add(src.len())
        .ok_or(CaliptraCompletionCode::InsufficientResources)?;
    if end > out.len() {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }
    out[*offset..end].copy_from_slice(src);
    *offset = end;
    Ok(())
}

async fn verify_fe_prog_mac(partition: u32, mac: &[u8; 48]) -> CaliptraVdmResult<()> {
    let challenge = AUTH_CHALLENGE
        .lock()
        .await
        .take()
        .ok_or(CaliptraCompletionCode::AccessDenied)?;

    let import_resp = Import::import(CmKeyUsage::Hmac, &TEST_AUTH_CMD_HMAC_KEY)
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

    let hmac_resp = Hmac::hmac(&import_resp.cmk, hmac_input.as_slice())
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let computed_mac = &hmac_resp.mac.as_bytes()[..48];
    if constant_time_eq(computed_mac, mac) {
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

fn map_idev_csr_error(e: CaliptraApiError) -> CaliptraCompletionCode {
    match e {
        CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
        CaliptraApiError::UnprovisionedCsr => CaliptraCompletionCode::InvalidState,
        CaliptraApiError::BufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
        CaliptraApiError::InvalidResponse
        | CaliptraApiError::Mailbox(_)
        | CaliptraApiError::Syscall(_) => CaliptraCompletionCode::OperationFailed,
        _ => CaliptraCompletionCode::GeneralError,
    }
}

fn map_caliptra_api_error(e: CaliptraApiError) -> CaliptraCompletionCode {
    match e {
        CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
        CaliptraApiError::BufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
        CaliptraApiError::InvalidResponse
        | CaliptraApiError::Mailbox(_)
        | CaliptraApiError::Syscall(_) => CaliptraCompletionCode::OperationFailed,
        _ => CaliptraCompletionCode::GeneralError,
    }
}
