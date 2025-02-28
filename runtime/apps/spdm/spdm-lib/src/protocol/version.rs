// Licensed under the Apache-2.0 license

use crate::error::SpdmError;

#[derive(Debug, Default, PartialEq, Clone, Copy, PartialOrd)]
pub enum SpdmVersion {
    #[default]
    V10,
    V11,
    V12,
    V13,
}

impl TryFrom<u8> for SpdmVersion {
    type Error = SpdmError;
    fn try_from(value: u8) -> Result<Self, SpdmError> {
        match value {
            0x10 => Ok(SpdmVersion::V10),
            0x11 => Ok(SpdmVersion::V11),
            0x12 => Ok(SpdmVersion::V12),
            0x13 => Ok(SpdmVersion::V13),
            _ => Err(SpdmError::UnsupportedVersion),
        }
    }
}

impl From<SpdmVersion> for u8 {
    fn from(version: SpdmVersion) -> Self {
        version.to_u8()
    }
}

impl SpdmVersion {
    fn to_u8(self) -> u8 {
        match self {
            SpdmVersion::V10 => 0x10,
            SpdmVersion::V11 => 0x11,
            SpdmVersion::V12 => 0x12,
            SpdmVersion::V13 => 0x13,
        }
    }

    pub fn major(&self) -> u8 {
        self.to_u8() >> 4
    }

    pub fn minor(&self) -> u8 {
        self.to_u8() & 0x0F
    }
}
