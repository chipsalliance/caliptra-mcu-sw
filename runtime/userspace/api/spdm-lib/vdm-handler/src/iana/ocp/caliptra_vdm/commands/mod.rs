// Licensed under the Apache-2.0 license

//! Per-command handlers for the Caliptra VDM protocol.

use caliptra_mcu_common_commands::{
    AsymAlgo, CaliptraCmdHandler, CaliptraCompletionCode as CommonCompletionCode,
    ProvisionIdevCertMode,
};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use zerocopy::byteorder::little_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout};

pub(crate) mod authorized_command;
pub(crate) mod debug_unlock;
#[cfg(feature = "device-ownership-transfer")]
pub(crate) mod device_ownership_transfer;
#[cfg(feature = "attested-csr")]
pub(crate) mod export_attested_csr;
pub(crate) mod get_attestation;

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct ProvisionIdevCertHdr {
    algorithm: U32,
    mode: U32,
    data_len: U32,
}

/// Handles `PROVISION_IDEV_CERT (0x09)`:
/// `[algorithm: u32, mode: u32, data_len: u32, data[..data_len]]`.
pub(crate) async fn handle_provision_idevid_cert<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Ok((hdr, data)) = ProvisionIdevCertHdr::ref_from_prefix(req) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let data_len = hdr.data_len.get() as usize;
    if data_len == 0 || data.len() != data_len {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let (Ok(algorithm), Ok(mode)) = (
        AsymAlgo::try_from(hdr.algorithm.get()),
        ProvisionIdevCertMode::try_from(hdr.mode.get()),
    ) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter);
    };
    match cmds
        .provision_idevid_cert(scratch.allocator(), algorithm, mode, data)
        .await
    {
        Ok(()) => match write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(map_common_completion(code)),
    }
}

pub(crate) fn write_success(out: &mut [u8]) -> Result<&mut [u8], CaliptraCompletionCode> {
    let Some((completion, rest)) = out.split_first_mut() else {
        return Err(CaliptraCompletionCode::InsufficientResources);
    };
    *completion = CaliptraCompletionCode::Success as u8;
    Ok(rest)
}

pub(crate) fn map_common_completion(code: CommonCompletionCode) -> CaliptraCompletionCode {
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
