// Licensed under the Apache-2.0 license

//! Per-command handlers for the Caliptra VDM protocol.
//!
//! Each handler decodes its command-specific request, invokes the platform
//! [`CaliptraVdmCommands`](super::CaliptraVdmCommands) PAL hook, and writes the
//! VDM response payload `[completion_code, command_data..]`.

use crate::iana::ocp::caliptra_vdm::protocol::CaliptraCompletionCode;

pub(crate) mod authorized_command;
pub(crate) mod clear_attestation_log;
pub(crate) mod clear_debug_log;
pub(crate) mod device_capabilities;
pub(crate) mod device_id;
pub(crate) mod device_info;
pub(crate) mod export_attested_csr;
pub(crate) mod export_idevid_csr;
pub(crate) mod firmware_version;
pub(crate) mod get_attestation_log;
pub(crate) mod get_debug_log;

pub(crate) const LOG_TYPE_DEBUG: u32 = 0;
pub(crate) const LOG_TYPE_ATTESTATION: u32 = 1;

pub(crate) fn require_empty(req: &[u8]) -> Result<(), CaliptraCompletionCode> {
    if req.is_empty() {
        Ok(())
    } else {
        Err(CaliptraCompletionCode::InvalidPayloadSize)
    }
}

pub(crate) fn read_u32_le(req: &[u8]) -> Result<u32, CaliptraCompletionCode> {
    let bytes: [u8; 4] = req
        .try_into()
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn read_optional_u32_le(req: &[u8]) -> Result<u32, CaliptraCompletionCode> {
    if req.is_empty() {
        Ok(0)
    } else {
        read_u32_le(req)
    }
}

pub(crate) fn write_success(out: &mut [u8]) -> Result<&mut [u8], CaliptraCompletionCode> {
    let Some((completion, rest)) = out.split_first_mut() else {
        return Err(CaliptraCompletionCode::InsufficientResources);
    };
    *completion = CaliptraCompletionCode::Success as u8;
    Ok(rest)
}
