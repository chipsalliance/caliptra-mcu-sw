// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FirmwareBootType {
    Unknown = 0,
    Flash = 1,
    Streaming = 2,
    Network = 3,
}

impl TryFrom<u32> for FirmwareBootType {
    type Error = ErrorCode;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Unknown as u32 => Ok(Self::Unknown),
            value if value == Self::Flash as u32 => Ok(Self::Flash),
            value if value == Self::Streaming as u32 => Ok(Self::Streaming),
            value if value == Self::Network as u32 => Ok(Self::Network),
            _ => Err(ErrorCode::Invalid),
        }
    }
}

pub struct System {}

impl System {
    pub fn exit(code: u32) {
        DefaultSyscalls::command(DRIVER_NUM, cmd::EXIT, code, 0)
            .to_result::<(), ErrorCode>()
            .unwrap();
    }

    pub fn firmware_boot_type() -> Result<FirmwareBootType, ErrorCode> {
        let value = DefaultSyscalls::command(DRIVER_NUM, cmd::GET_FIRMWARE_BOOT_TYPE, 0, 0)
            .to_result::<u32, ErrorCode>()?;
        FirmwareBootType::try_from(value)
    }

    pub fn mcu_rom_capabilities() -> Result<u32, ErrorCode> {
        DefaultSyscalls::command(DRIVER_NUM, cmd::GET_MCU_ROM_CAPABILITIES, 0, 0)
            .to_result::<u32, ErrorCode>()
    }
}

pub const DRIVER_NUM: u32 = 0xC000_0000;

mod cmd {
    pub const EXIT: u32 = 1;
    pub const GET_FIRMWARE_BOOT_TYPE: u32 = 2;
    pub const GET_MCU_ROM_CAPABILITIES: u32 = 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_boot_type_encoding() {
        assert_eq!(FirmwareBootType::try_from(0), Ok(FirmwareBootType::Unknown));
        assert_eq!(FirmwareBootType::try_from(1), Ok(FirmwareBootType::Flash));
        assert_eq!(
            FirmwareBootType::try_from(2),
            Ok(FirmwareBootType::Streaming)
        );
        assert_eq!(FirmwareBootType::try_from(3), Ok(FirmwareBootType::Network));
        assert_eq!(FirmwareBootType::try_from(4), Err(ErrorCode::Invalid));
    }
}
