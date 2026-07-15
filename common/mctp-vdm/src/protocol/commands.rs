// Licensed under the Apache-2.0 license

use crate::error::VdmError;
use core::convert::TryFrom;

/// MCTP VDM Command codes as defined in the external MCTP VDM commands spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VdmCommand {
    FirmwareVersion = 0x01,
    DeviceCapabilities = 0x02,
    GetDebugLog = 0x03,
    ClearDebugLog = 0x04,
}

impl TryFrom<u8> for VdmCommand {
    type Error = VdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(VdmCommand::FirmwareVersion),
            0x02 => Ok(VdmCommand::DeviceCapabilities),
            0x03 => Ok(VdmCommand::GetDebugLog),
            0x04 => Ok(VdmCommand::ClearDebugLog),
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
    VdmCommand::GetDebugLog,
    VdmCommand::ClearDebugLog,
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
        assert_eq!(VdmCommand::try_from(0x03), Ok(VdmCommand::GetDebugLog));
        assert_eq!(VdmCommand::try_from(0x04), Ok(VdmCommand::ClearDebugLog));
        assert_eq!(
            VdmCommand::try_from(0xFF),
            Err(VdmError::UnsupportedCommand)
        );
    }

    #[test]
    fn test_command_into_u8() {
        assert_eq!(u8::from(VdmCommand::FirmwareVersion), 0x01);
        assert_eq!(u8::from(VdmCommand::DeviceCapabilities), 0x02);
        assert_eq!(u8::from(VdmCommand::GetDebugLog), 0x03);
        assert_eq!(u8::from(VdmCommand::ClearDebugLog), 0x04);
    }

    #[test]
    fn test_is_command_supported() {
        assert!(is_command_supported(VdmCommand::FirmwareVersion));
        assert!(is_command_supported(VdmCommand::DeviceCapabilities));
        assert!(is_command_supported(VdmCommand::GetDebugLog));
        assert!(is_command_supported(VdmCommand::ClearDebugLog));
    }
}
