// Licensed under the Apache-2.0 license

//! Per-command handlers for the Caliptra VDM protocol.

use caliptra_mcu_common_commands::CaliptraCompletionCode as CommonCompletionCode;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::CaliptraCompletionCode;

pub(crate) mod authorized_command;
pub(crate) mod debug_unlock;
pub(crate) mod export_attested_csr;

pub(crate) fn require_empty(req: &[u8]) -> Result<(), CaliptraCompletionCode> {
    if req.is_empty() {
        Ok(())
    } else {
        Err(CaliptraCompletionCode::InvalidPayloadSize)
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
