// Licensed under the Apache-2.0 license

use crate::codec::{CommonCodec, DataKind};
use crate::vdm_handler::VdmError;
pub use caliptra_mcu_common_commands::CaliptraCompletionCode;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// OCP Vendor ID for Caliptra Working Group (IANA assigned).
pub const OCP_VENDOR_ID: u32 = 42623; // 0xA67F

/// Caliptra VDM command version (first byte of every VDM payload).
pub const CALIPTRA_VDM_COMMAND_VERSION: u8 = 0x01;

/// Caliptra VDM command codes as defined in the OCP registry.
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
    type Error = VdmError;

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
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }
}

impl CaliptraVdmCommand {
    pub fn response_code(self) -> u8 {
        self as u8
    }
}

/// Caliptra VDM message header: [command_version, command_code].
#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C)]
pub struct CaliptraVdmMsgHeader {
    pub command_version: u8,
    pub command_code: u8,
}

impl CommonCodec for CaliptraVdmMsgHeader {
    const DATA_KIND: DataKind = DataKind::Header;
}

impl CaliptraVdmMsgHeader {
    #[allow(dead_code)]
    pub fn new_request(command: CaliptraVdmCommand) -> Self {
        Self {
            command_version: CALIPTRA_VDM_COMMAND_VERSION,
            command_code: command as u8,
        }
    }

    #[allow(dead_code)]
    pub fn new_response(command: CaliptraVdmCommand) -> Self {
        Self {
            command_version: CALIPTRA_VDM_COMMAND_VERSION,
            command_code: command.response_code(),
        }
    }
}

/// Result type for individual command handlers.
#[derive(Debug)]
pub enum CaliptraVdmCmdResult {
    Response(usize),
    ErrorResponse(CaliptraCompletionCode),
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
}
