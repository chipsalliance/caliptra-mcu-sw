// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::fuses;

#[repr(u32)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum PartitionId {
    SwTestUnlock = 0x00,
    SecretManuf = 0x01,
    SecretProd0 = 0x02,
    SecretProd1 = 0x03,
    SecretProd2 = 0x04,
    SecretProd3 = 0x05,
    SwManuf = 0x06,
    SecretLcTransition = 0x07,
    Svn = 0x08,
    VendorTest = 0x09,
    VendorHashesManuf = 0x0A,
    VendorHashesProd = 0x0B,
    VendorRevocationsProd = 0x0C,
    VendorSecretProd = 0x0D,
    VendorNonSecretProd = 0x0E,
}

impl TryFrom<u32> for PartitionId {
    type Error = McuError;

    fn try_from(v: u32) -> Result<Self, McuError> {
        match v {
            0x00 => Ok(Self::SwTestUnlock),
            0x01 => Ok(Self::SecretManuf),
            0x02 => Ok(Self::SecretProd0),
            0x03 => Ok(Self::SecretProd1),
            0x04 => Ok(Self::SecretProd2),
            0x05 => Ok(Self::SecretProd3),
            0x06 => Ok(Self::SwManuf),
            0x07 => Ok(Self::SecretLcTransition),
            0x08 => Ok(Self::Svn),
            0x09 => Ok(Self::VendorTest),
            0x0A => Ok(Self::VendorHashesManuf),
            0x0B => Ok(Self::VendorHashesProd),
            0x0C => Ok(Self::VendorRevocationsProd),
            0x0D => Ok(Self::VendorSecretProd),
            0x0E => Ok(Self::VendorNonSecretProd),
            _ => Err(McuError::ROM_OTP_FUSE_INVALID_PARTITION),
        }
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PartitionInfo {
    pub byte_offset: usize,
    pub byte_size: usize,
    pub is_secret: bool,
}

impl PartitionId {
    pub fn info(self) -> PartitionInfo {
        use PartitionId::*;
        match self {
            SwTestUnlock => PartitionInfo {
                byte_offset: fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET,
                byte_size: fuses::SW_TEST_UNLOCK_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            SecretManuf => PartitionInfo {
                byte_offset: fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET,
                byte_size: fuses::SECRET_MANUF_PARTITION_BYTE_SIZE,
                is_secret: true,
            },
            SecretProd0 => PartitionInfo {
                byte_offset: fuses::SECRET_PROD_PARTITION_0_BYTE_OFFSET,
                byte_size: fuses::SECRET_PROD_PARTITION_0_BYTE_SIZE,
                is_secret: true,
            },
            SecretProd1 => PartitionInfo {
                byte_offset: fuses::SECRET_PROD_PARTITION_1_BYTE_OFFSET,
                byte_size: fuses::SECRET_PROD_PARTITION_1_BYTE_SIZE,
                is_secret: true,
            },
            SecretProd2 => PartitionInfo {
                byte_offset: fuses::SECRET_PROD_PARTITION_2_BYTE_OFFSET,
                byte_size: fuses::SECRET_PROD_PARTITION_2_BYTE_SIZE,
                is_secret: true,
            },
            SecretProd3 => PartitionInfo {
                byte_offset: fuses::SECRET_PROD_PARTITION_3_BYTE_OFFSET,
                byte_size: fuses::SECRET_PROD_PARTITION_3_BYTE_SIZE,
                is_secret: true,
            },
            SwManuf => PartitionInfo {
                byte_offset: fuses::SW_MANUF_PARTITION_BYTE_OFFSET,
                byte_size: fuses::SW_MANUF_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            SecretLcTransition => PartitionInfo {
                byte_offset: fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET,
                byte_size: fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_SIZE,
                is_secret: true,
            },
            Svn => PartitionInfo {
                byte_offset: fuses::SVN_PARTITION_BYTE_OFFSET,
                byte_size: fuses::SVN_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            VendorTest => PartitionInfo {
                byte_offset: fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET,
                byte_size: fuses::VENDOR_TEST_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            VendorHashesManuf => PartitionInfo {
                byte_offset: fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET,
                byte_size: fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            VendorHashesProd => PartitionInfo {
                byte_offset: fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_OFFSET,
                byte_size: fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            VendorRevocationsProd => PartitionInfo {
                byte_offset: fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET,
                byte_size: fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
            VendorSecretProd => PartitionInfo {
                byte_offset: fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_OFFSET,
                byte_size: fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_SIZE,
                is_secret: true,
            },
            VendorNonSecretProd => PartitionInfo {
                byte_offset: fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET,
                byte_size: fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE,
                is_secret: false,
            },
        }
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct FuseReadParams {
    pub base_word_addr: usize,
    pub words_to_read: usize,
    pub valid_bits: u32,
}

pub fn fuse_read_dai_params(
    partition: u32,
    entry: u32,
    max_words: usize,
) -> Result<FuseReadParams, McuError> {
    let info = PartitionId::try_from(partition)?.info();

    if info.is_secret {
        return Err(McuError::ROM_OTP_FUSE_SECRET_READ_DENIED);
    }

    let entry_offset = entry as usize;
    if entry_offset >= info.byte_size || entry_offset % 4 != 0 {
        return Err(McuError::ROM_OTP_FUSE_ENTRY_OUT_OF_BOUNDS);
    }

    let remaining_bytes = info.byte_size - entry_offset;
    let remaining_words = (remaining_bytes + 3) / 4;
    let words_to_read = remaining_words.min(max_words);
    let base_word_addr = (info.byte_offset + entry_offset) / 4;
    let valid_bits = (remaining_bytes.min(words_to_read * 4) * 8) as u32;

    Ok(FuseReadParams {
        base_word_addr,
        words_to_read,
        valid_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_partition() {
        let err = PartitionId::try_from(0x0f).unwrap_err();

        assert_eq!(err, McuError::ROM_OTP_FUSE_INVALID_PARTITION);
    }

    #[test]
    fn denies_secret_partition_reads() {
        let err = fuse_read_dai_params(PartitionId::SecretManuf as u32, 0, 1).unwrap_err();

        assert_eq!(err, McuError::ROM_OTP_FUSE_SECRET_READ_DENIED);
    }

    #[test]
    fn rejects_unaligned_or_out_of_bounds_entry() {
        let info = PartitionId::Svn.info();
        let unaligned_err = fuse_read_dai_params(PartitionId::Svn as u32, 1, 1).unwrap_err();
        let out_of_bounds_err =
            fuse_read_dai_params(PartitionId::Svn as u32, info.byte_size as u32, 1).unwrap_err();

        assert_eq!(unaligned_err, McuError::ROM_OTP_FUSE_ENTRY_OUT_OF_BOUNDS);
        assert_eq!(
            out_of_bounds_err,
            McuError::ROM_OTP_FUSE_ENTRY_OUT_OF_BOUNDS
        );
    }

    #[test]
    fn calculates_read_params() {
        let info = PartitionId::VendorNonSecretProd.info();
        let params = fuse_read_dai_params(PartitionId::VendorNonSecretProd as u32, 4, 3).unwrap();
        let remaining_bytes = info.byte_size - 4;

        assert_eq!(params.base_word_addr, (info.byte_offset + 4) / 4);
        assert_eq!(params.words_to_read, ((remaining_bytes + 3) / 4).min(3));
        assert_eq!(
            params.valid_bits,
            (remaining_bytes.min(params.words_to_read * 4) * 8) as u32
        );
    }
}
