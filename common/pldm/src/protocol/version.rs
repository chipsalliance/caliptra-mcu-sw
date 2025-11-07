// Licensed under the Apache-2.0 license

use crate::error::PldmError;
use core::convert::TryFrom;

pub type Ver32 = u32;
pub type VersionCheckSum = u32;
pub type ProtocolVersionStr = &'static str;

// The PLDM base protocol version 1.1.0
pub const PLDM_BASE_PROTOCOL_VERSION: ProtocolVersionStr = "1.1.0";

// PLDM firmware update protocol 1.3.0
pub const PLDM_FW_UPDATE_PROTOCOL_VERSION: ProtocolVersionStr = "1.3.0";

/// PLDM version structure. Ver32 encoding
///
/// The "major," "minor," and "update" bytes are BCD-encoded, and each byte holds two BCD
/// digits. The "alpha" byte holds an optional alphanumeric character extension that is encoded using the
/// ISO/IEC 8859-1 Character Set. The value 0xF in the most-significant nibble of a BCD-encoded value indicates that the most
/// significant nibble should be ignored and the overall field treated as a single-digit value. Software
/// or utilities that display the number should display only a single digit and should not put in a
/// leading "0" when displaying the number.
///
/// A value of 0xFF in the "update" field indicates that the entire field is not present. 0xFF is not
/// allowed as a value for the "major" or "minor" fields. Software or utilities that display the version
/// number should not display any characters for this field.
///
/// For example:
/// - Version 3.7.10a → 0xF3F71061
///
/// - Version 3.1 → 0xF3F1FF00
/// - Version 1.0a → 0xF1F0FF61
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct PldmVersion {
    pub alpha: u8,
    pub update: u8,
    pub minor: u8,
    pub major: u8,
}

impl TryFrom<ProtocolVersionStr> for PldmVersion {
    type Error = PldmError;

    fn try_from(version: ProtocolVersionStr) -> Result<Self, PldmError> {
        let mut parts = version.split('.');
        let major_str = parts.next().ok_or(PldmError::InvalidProtocolVersion)?;
        let minor_str = parts.next().ok_or(PldmError::InvalidProtocolVersion)?;
        let update_str = parts.next().unwrap_or("FF");

        if parts.next().is_some() {
            return Err(PldmError::InvalidProtocolVersion);
        }

        let (alpha, minor_str) = if let Some(last_char) = minor_str.chars().last() {
            if last_char.is_alphabetic() {
                (last_char as u8, &minor_str[..minor_str.len() - 1])
            } else {
                (0, minor_str)
            }
        } else {
            (0, minor_str)
        };

        let (alpha, update_str) = if update_str != "FF" {
            if let Some(last_char) = update_str.chars().last() {
                if last_char.is_alphabetic() {
                    (last_char as u8, &update_str[..update_str.len() - 1])
                } else {
                    (alpha, update_str)
                }
            } else {
                (alpha, update_str)
            }
        } else {
            (alpha, update_str)
        };

        let major = major_str
            .parse::<u8>()
            .map_err(|_| PldmError::InvalidProtocolVersion)?;
        let minor = minor_str
            .parse::<u8>()
            .map_err(|_| PldmError::InvalidProtocolVersion)?;
        let update = if update_str == "FF" {
            0xFF
        } else {
            update_str
                .parse::<u8>()
                .map_err(|_| PldmError::InvalidProtocolVersion)?
        };

        Ok(PldmVersion {
            alpha,
            update,
            minor,
            major,
        })
    }
}

impl PldmVersion {
    pub fn new(alpha: u8, update: u8, minor: u8, major: u8) -> Self {
        PldmVersion {
            alpha,
            update,
            minor,
            major,
        }
    }

    pub fn bcd_encode_to_ver32(&self) -> Ver32 {
        let major_bcd = if self.major < 10 {
            0xF0 | self.major
        } else {
            ((self.major / 10) << 4) | (self.major % 10)
        };
        let minor_bcd = if self.minor < 10 {
            0xF0 | self.minor
        } else {
            ((self.minor / 10) << 4) | (self.minor % 10)
        };
        let update_bcd = if self.update == 0xFF {
            0xFF
        } else if self.update < 10 {
            0xF0 | self.update
        } else {
            ((self.update / 10) << 4) | (self.update % 10)
        };
        let alpha_bcd = self.alpha; // Alpha is directly used as it's already in the correct format or 0x00 if not present

        ((major_bcd as u32) << 24)
            | ((minor_bcd as u32) << 16)
            | ((update_bcd as u32) << 8)
            | alpha_bcd as u32
    }

    pub fn bcd_decode_from_ver32(encoded_ver32: Ver32) -> Self {
        let major_bcd = ((encoded_ver32 >> 24) & 0xFF) as u8;
        let minor_bcd = ((encoded_ver32 >> 16) & 0xFF) as u8;
        let update_bcd = ((encoded_ver32 >> 8) & 0xFF) as u8;
        let alpha = (encoded_ver32 & 0xFF) as u8;

        let major = if major_bcd >> 4 == 0xF {
            major_bcd & 0x0F
        } else {
            ((major_bcd >> 4) * 10) + (major_bcd & 0x0F)
        };
        let minor = if minor_bcd >> 4 == 0xF {
            minor_bcd & 0x0F
        } else {
            ((minor_bcd >> 4) * 10) + (minor_bcd & 0x0F)
        };
        let update = if update_bcd == 0xFF {
            update_bcd
        } else if update_bcd >> 4 == 0xF {
            update_bcd & 0x0F
        } else {
            ((update_bcd >> 4) * 10) + (update_bcd & 0x0F)
        };

        PldmVersion {
            alpha,
            update,
            minor,
            major,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pldm_version_try_from_str() {
        let test_version = PldmVersion::try_from("3.7.10").unwrap();
        assert_eq!(test_version, PldmVersion::new(0, 10, 7, 3));

        let test_version = PldmVersion::try_from("3.7").unwrap();
        assert_eq!(test_version, PldmVersion::new(0, 0xFF, 7, 3));

        let test_version = PldmVersion::try_from("1.1.0").unwrap();
        assert_eq!(test_version, PldmVersion::new(0, 0, 1, 1));

        let test_version = PldmVersion::try_from("1.3.0").unwrap();
        assert_eq!(test_version, PldmVersion::new(0, 0, 3, 1));

        let test_version = PldmVersion::try_from("1.5.18a").unwrap();
        assert_eq!(test_version, PldmVersion::new(0x61, 18, 5, 1));

        let test_version = PldmVersion::try_from("1.5a").unwrap();
        assert_eq!(test_version, PldmVersion::new(0x61, 0xFF, 5, 1));
    }

    #[test]
    fn test_pldm_version_try_from_str_error() {
        let test_version = PldmVersion::try_from("3.FF.10");
        assert!(test_version.is_err());

        let test_version = PldmVersion::try_from("3.7.10a.1");
        assert!(test_version.is_err());

        let test_version = PldmVersion::try_from("3.7.10a.1.1");
        assert!(test_version.is_err());

        let test_version = PldmVersion::try_from("3a.7.10");
        assert!(test_version.is_err());
    }

    #[test]
    fn test_pldm_version_bcd_encode() {
        let test_version1 = PldmVersion::new(0x61, 0x10, 0x7, 0x3);
        assert_eq!(test_version1.bcd_encode_to_ver32(), 0xF3F71661);

        let test_version2 = PldmVersion::new(0x61, 0xFF, 0x1, 0x3);
        assert_eq!(test_version2.bcd_encode_to_ver32(), 0xF3F1FF61);

        let test_version3 = PldmVersion::new(0x61, 0xFF, 0xa, 0x1);
        assert_eq!(test_version3.bcd_encode_to_ver32(), 0xF110FF61);
    }

    #[test]
    fn test_pldm_version_bcd_decode_from_ver32() {
        let test_version1 = PldmVersion::bcd_decode_from_ver32(0xF3F71661);
        assert_eq!(test_version1, PldmVersion::new(0x61, 0x10, 0x7, 0x3));

        let test_version2 = PldmVersion::bcd_decode_from_ver32(0xF3F1FF61);
        assert_eq!(test_version2, PldmVersion::new(0x61, 0xFF, 0x1, 0x3));

        let test_version3 = PldmVersion::bcd_decode_from_ver32(0xF1F0FF62);
        assert_eq!(test_version3, PldmVersion::new(0x62, 0xFF, 0x0, 0x1));
    }

    #[test]
    fn test_pldm_version_str_to_ver32() {
        let test_version1 = "1.3.0";
        let test_version1_ver32 = PldmVersion::try_from(test_version1)
            .unwrap()
            .bcd_encode_to_ver32();
        assert_eq!(test_version1_ver32, 0xF1F3F000);

        let test_version2 = "1.1.0";
        let test_version2_ver32 = PldmVersion::try_from(test_version2)
            .unwrap()
            .bcd_encode_to_ver32();
        assert_eq!(test_version2_ver32, 0xF1F1F000);
    }
}
