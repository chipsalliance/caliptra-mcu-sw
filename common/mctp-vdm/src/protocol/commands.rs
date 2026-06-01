// Licensed under the Apache-2.0 license

use crate::error::VdmError;
use core::convert::TryFrom;

/// MCTP VDM Command codes as defined in the external MCTP VDM commands spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VdmCommand {
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

impl TryFrom<u8> for VdmCommand {
    type Error = VdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(VdmCommand::FirmwareVersion),
            0x02 => Ok(VdmCommand::DeviceCapabilities),
            0x03 => Ok(VdmCommand::DeviceId),
            0x04 => Ok(VdmCommand::DeviceInfo),
            0x05 => Ok(VdmCommand::GetDebugLog),
            0x06 => Ok(VdmCommand::ClearDebugLog),
            0x07 => Ok(VdmCommand::GetAttestationLog),
            0x08 => Ok(VdmCommand::ClearAttestationLog),
            0x09 => Ok(VdmCommand::GetAttestation),
            0x0A => Ok(VdmCommand::RequestDebugUnlock),
            0x0B => Ok(VdmCommand::AuthorizeDebugUnlockToken),
            0x0C => Ok(VdmCommand::ExportIdevidCsr),
            0x0D => Ok(VdmCommand::SetSlot0Cert),
            0x0E => Ok(VdmCommand::GetSlot0State),
            0x0F => Ok(VdmCommand::ExportAttestedCsr),
            0x10 => Ok(VdmCommand::ProgramFieldEntropy),
            0x11 => Ok(VdmCommand::DeviceOwnershipTransfer),
            _ => Err(VdmError::UnsupportedCommand),
        }
    }
}

impl From<VdmCommand> for u8 {
    fn from(cmd: VdmCommand) -> Self {
        cmd as u8
    }
}

// Commands currently supported in the initial implementation.
pub const SUPPORTED_COMMANDS: &[VdmCommand] = &[
    VdmCommand::FirmwareVersion,
    VdmCommand::DeviceCapabilities,
    VdmCommand::DeviceId,
    VdmCommand::DeviceInfo,
];

/// Check if a command is supported in the current implementation.
pub fn is_command_supported(cmd: VdmCommand) -> bool {
    SUPPORTED_COMMANDS.contains(&cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_try_from() {
        assert_eq!(VdmCommand::try_from(0x01), Ok(VdmCommand::FirmwareVersion));
        assert_eq!(
            VdmCommand::try_from(0x02),
            Ok(VdmCommand::DeviceCapabilities)
        );
        assert_eq!(VdmCommand::try_from(0x03), Ok(VdmCommand::DeviceId));
        assert_eq!(VdmCommand::try_from(0x04), Ok(VdmCommand::DeviceInfo));
        assert_eq!(VdmCommand::try_from(0x05), Ok(VdmCommand::GetDebugLog));
        assert_eq!(VdmCommand::try_from(0x06), Ok(VdmCommand::ClearDebugLog));
        assert_eq!(
            VdmCommand::try_from(0x07),
            Ok(VdmCommand::GetAttestationLog)
        );
        assert_eq!(
            VdmCommand::try_from(0x08),
            Ok(VdmCommand::ClearAttestationLog)
        );
        assert_eq!(VdmCommand::try_from(0x09), Ok(VdmCommand::GetAttestation));
        assert_eq!(
            VdmCommand::try_from(0x0A),
            Ok(VdmCommand::RequestDebugUnlock)
        );
        assert_eq!(
            VdmCommand::try_from(0x0B),
            Ok(VdmCommand::AuthorizeDebugUnlockToken)
        );
        assert_eq!(VdmCommand::try_from(0x0C), Ok(VdmCommand::ExportIdevidCsr));
        assert_eq!(VdmCommand::try_from(0x0D), Ok(VdmCommand::SetSlot0Cert));
        assert_eq!(VdmCommand::try_from(0x0E), Ok(VdmCommand::GetSlot0State));
        assert_eq!(
            VdmCommand::try_from(0x0F),
            Ok(VdmCommand::ExportAttestedCsr)
        );
        assert_eq!(
            VdmCommand::try_from(0x10),
            Ok(VdmCommand::ProgramFieldEntropy)
        );
        assert_eq!(
            VdmCommand::try_from(0x11),
            Ok(VdmCommand::DeviceOwnershipTransfer)
        );
        assert_eq!(
            VdmCommand::try_from(0xFF),
            Err(VdmError::UnsupportedCommand)
        );
    }

    #[test]
    fn test_command_into_u8() {
        assert_eq!(u8::from(VdmCommand::FirmwareVersion), 0x01);
        assert_eq!(u8::from(VdmCommand::DeviceCapabilities), 0x02);
        assert_eq!(u8::from(VdmCommand::DeviceId), 0x03);
        assert_eq!(u8::from(VdmCommand::DeviceInfo), 0x04);
        assert_eq!(u8::from(VdmCommand::GetDebugLog), 0x05);
        assert_eq!(u8::from(VdmCommand::ClearDebugLog), 0x06);
        assert_eq!(u8::from(VdmCommand::GetAttestationLog), 0x07);
        assert_eq!(u8::from(VdmCommand::ClearAttestationLog), 0x08);
        assert_eq!(u8::from(VdmCommand::GetAttestation), 0x09);
        assert_eq!(u8::from(VdmCommand::RequestDebugUnlock), 0x0A);
        assert_eq!(u8::from(VdmCommand::AuthorizeDebugUnlockToken), 0x0B);
        assert_eq!(u8::from(VdmCommand::ExportIdevidCsr), 0x0C);
        assert_eq!(u8::from(VdmCommand::SetSlot0Cert), 0x0D);
        assert_eq!(u8::from(VdmCommand::GetSlot0State), 0x0E);
        assert_eq!(u8::from(VdmCommand::ExportAttestedCsr), 0x0F);
        assert_eq!(u8::from(VdmCommand::ProgramFieldEntropy), 0x10);
        assert_eq!(u8::from(VdmCommand::DeviceOwnershipTransfer), 0x11);
    }

    #[test]
    fn test_is_command_supported() {
        assert!(is_command_supported(VdmCommand::FirmwareVersion));
        assert!(is_command_supported(VdmCommand::DeviceCapabilities));
        assert!(is_command_supported(VdmCommand::DeviceId));
        assert!(is_command_supported(VdmCommand::DeviceInfo));
        assert!(!is_command_supported(VdmCommand::ExportAttestedCsr));
        assert!(!is_command_supported(VdmCommand::GetDebugLog));
        assert!(!is_command_supported(VdmCommand::ClearDebugLog));
    }
}
