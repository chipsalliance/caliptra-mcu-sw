// Licensed under the Apache-2.0 license

//! Caliptra VDM protocol definitions — transport-agnostic.
//!
//! These constants and types match the MCU responder's CaliptraVdmHandler.
//! They define the wire format for Caliptra vendor-defined messages regardless
//! of whether the underlying transport is SPDM VDM or MCTP VDM.

/// OCP Vendor ID for Caliptra Working Group (IANA assigned).
pub const OCP_VENDOR_ID: u32 = 0xA67F;

/// SPDM/MCTP StandardsBodyId for IANA-registered vendors.
pub const REGISTRY_ID_IANA: u16 = 0x04;

/// Caliptra VDM command version (first byte of every VDM payload).
pub const CALIPTRA_VDM_COMMAND_VERSION: u8 = 0x01;

/// Minimum response size: [version, command_code, completion_code]
pub const VDM_RESPONSE_HEADER_SIZE: usize = 3;

/// Maximum response buffer size for vendor-defined messages.
pub const MAX_VDM_RESPONSE_SIZE: usize = 16384;

/// Caliptra VDM command codes as defined in the OCP registry.
///
/// These match the responder's `CaliptraVdmCommand` enum at
/// `runtime/userspace/api/spdm-lib/src/vdm_handler/iana/ocp/caliptra_vdm/protocol.rs`
///
/// Note: These are the wire-format command codes (u8), distinct from the internal
/// `CaliptraCommandId` (u32) used by the session/command layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaliptraVdmCommand {
    FirmwareVersion = 0x01,
    DeviceCapabilities = 0x02,
    DeviceId = 0x03,
    DeviceInfo = 0x04,
    GetDebugLog = 0x05,
    ClearDebugLog = 0x06,
    GetAttestationLog = 0x07,
    ClearAttestationLog = 0x08,
    GetAttestation = 0x09,
    RequestDebugUnlock = 0x0A,
    AuthorizeDebugUnlockToken = 0x0B,
    ExportIdevidCsr = 0x0C,
    SetSlot0Cert = 0x0D,
    GetSlot0State = 0x0E,
    ExportAttestedCsr = 0x0F,
    ProgramFieldEntropy = 0x10,
    DeviceOwnershipTransfer = 0x11,
}

impl TryFrom<u8> for CaliptraVdmCommand {
    type Error = SpdmVdmProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::FirmwareVersion),
            0x02 => Ok(Self::DeviceCapabilities),
            0x03 => Ok(Self::DeviceId),
            0x04 => Ok(Self::DeviceInfo),
            0x05 => Ok(Self::GetDebugLog),
            0x06 => Ok(Self::ClearDebugLog),
            0x07 => Ok(Self::GetAttestationLog),
            0x08 => Ok(Self::ClearAttestationLog),
            0x09 => Ok(Self::GetAttestation),
            0x0A => Ok(Self::RequestDebugUnlock),
            0x0B => Ok(Self::AuthorizeDebugUnlockToken),
            0x0C => Ok(Self::ExportIdevidCsr),
            0x0D => Ok(Self::SetSlot0Cert),
            0x0E => Ok(Self::GetSlot0State),
            0x0F => Ok(Self::ExportAttestedCsr),
            0x10 => Ok(Self::ProgramFieldEntropy),
            0x11 => Ok(Self::DeviceOwnershipTransfer),
            _ => Err(SpdmVdmProtocolError::UnknownCommand(value)),
        }
    }
}

/// Caliptra VDM completion codes (OCP error codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaliptraVdmCompletionCode {
    Success = 0x00,
    GeneralError = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidIdentifier = 0x04,
    OperationFailed = 0x05,
    InsufficientResources = 0x06,
    UnsupportedOperation = 0x07,
    DeviceNotReady = 0x08,
    InvalidCommandVersion = 0x09,
    InvalidPayloadSize = 0x0A,
    Timeout = 0x0B,
    AccessDenied = 0x0C,
    ResourceUnavailable = 0x0D,
    PolicyViolation = 0x0E,
    InvalidState = 0x0F,

    // Caliptra project-specific codes (0xC0-0xFF)
    CaliptraMailboxBusy = 0xC0,
    CaliptraBufferTooSmall = 0xC1,
}

impl TryFrom<u8> for CaliptraVdmCompletionCode {
    type Error = SpdmVdmProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Success),
            0x01 => Ok(Self::GeneralError),
            0x02 => Ok(Self::InvalidParameter),
            0x03 => Ok(Self::InvalidLength),
            0x04 => Ok(Self::InvalidIdentifier),
            0x05 => Ok(Self::OperationFailed),
            0x06 => Ok(Self::InsufficientResources),
            0x07 => Ok(Self::UnsupportedOperation),
            0x08 => Ok(Self::DeviceNotReady),
            0x09 => Ok(Self::InvalidCommandVersion),
            0x0A => Ok(Self::InvalidPayloadSize),
            0x0B => Ok(Self::Timeout),
            0x0C => Ok(Self::AccessDenied),
            0x0D => Ok(Self::ResourceUnavailable),
            0x0E => Ok(Self::PolicyViolation),
            0x0F => Ok(Self::InvalidState),
            0xC0 => Ok(Self::CaliptraMailboxBusy),
            0xC1 => Ok(Self::CaliptraBufferTooSmall),
            _ => Err(SpdmVdmProtocolError::UnknownCompletionCode(value)),
        }
    }
}

/// Protocol-level errors for Caliptra VDM wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmVdmProtocolError {
    UnknownCommand(u8),
    UnknownCompletionCode(u8),
}

/// Map internal CaliptraCommandId (u32) to wire-format CaliptraVdmCommand (u8).
///
/// Returns `None` for command IDs not supported over the VDM transport.
pub fn command_id_to_vdm(command_id: u32) -> Option<CaliptraVdmCommand> {
    use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
    match command_id {
        x if x == CaliptraCommandId::GetFirmwareVersion as u32 => {
            Some(CaliptraVdmCommand::FirmwareVersion)
        }
        x if x == CaliptraCommandId::GetDeviceCapabilities as u32 => {
            Some(CaliptraVdmCommand::DeviceCapabilities)
        }
        x if x == CaliptraCommandId::GetDeviceId as u32 => Some(CaliptraVdmCommand::DeviceId),
        x if x == CaliptraCommandId::GetDeviceInfo as u32 => Some(CaliptraVdmCommand::DeviceInfo),
        x if x == CaliptraCommandId::ExportAttestedCsr as u32 => {
            Some(CaliptraVdmCommand::ExportAttestedCsr)
        }
        x if x == CaliptraCommandId::ExportIdevidCsr as u32 => {
            Some(CaliptraVdmCommand::ExportIdevidCsr)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_roundtrip() {
        for code in 0x01u8..=0x11 {
            let cmd = CaliptraVdmCommand::try_from(code).unwrap();
            assert_eq!(cmd as u8, code);
        }
        assert!(CaliptraVdmCommand::try_from(0x00).is_err());
        assert!(CaliptraVdmCommand::try_from(0x12).is_err());
        assert!(CaliptraVdmCommand::try_from(0xFF).is_err());
    }

    #[test]
    fn test_completion_code_roundtrip() {
        for code in 0x00u8..=0x0F {
            let cc = CaliptraVdmCompletionCode::try_from(code).unwrap();
            assert_eq!(cc as u8, code);
        }
        assert_eq!(
            CaliptraVdmCompletionCode::try_from(0xC0).unwrap(),
            CaliptraVdmCompletionCode::CaliptraMailboxBusy
        );
        assert_eq!(
            CaliptraVdmCompletionCode::try_from(0xC1).unwrap(),
            CaliptraVdmCompletionCode::CaliptraBufferTooSmall
        );
        assert!(CaliptraVdmCompletionCode::try_from(0x10).is_err());
    }

    #[test]
    fn test_command_id_mapping() {
        use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
        assert_eq!(
            command_id_to_vdm(CaliptraCommandId::GetDeviceId as u32),
            Some(CaliptraVdmCommand::DeviceId)
        );
        assert_eq!(
            command_id_to_vdm(CaliptraCommandId::ExportAttestedCsr as u32),
            Some(CaliptraVdmCommand::ExportAttestedCsr)
        );
        // Unsupported command
        assert_eq!(command_id_to_vdm(CaliptraCommandId::HashInit as u32), None);
    }
}
