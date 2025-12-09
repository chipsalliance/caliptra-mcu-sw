// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use core::convert::From;
use core::num::{NonZeroU32, TryFromIntError};

/// MCU Error Type
/// Derives debug, copy, clone, eq, and partial eq
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct McuError(pub NonZeroU32);

/// Macro to define error constants ensuring uniqueness
///
/// This macro takes a list of (name, value, doc) tuples and generates
/// constant definitions for each error code.
#[macro_export]
macro_rules! define_error_constants {
    ($(($name:ident, $value:expr, $doc:expr)),* $(,)?) => {
        $(
            #[doc = $doc]
            pub const $name: McuError = McuError::new_const($value);
        )*

        #[cfg(test)]
        /// Returns a vector of all defined error constants for testing uniqueness
        pub fn all_constants() -> Vec<(& 'static str, u32)> {
            vec![
                $(
                    (stringify!($name), $value),
                )*
            ]
        }
    };
}

impl McuError {
    /// Create a MCU error; intended to only be used from const contexts, as we don't want
    /// runtime panics if val is zero. The preferred way to get a McuError from a u32 is to
    /// use `McuError::try_from()` from the `TryFrom` trait impl.
    const fn new_const(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("McuError cannot be 0"),
        }
    }

    /// Create an MCU error; intended to be used by vendors for vendor specific errors
    pub const fn new_vendor(val: u32) -> Self {
        Self(NonZeroU32::new(0xf000_0000 | val).unwrap())
    }

    // Use the macro to define all error constants
    define_error_constants![
        (
            ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY,
            0x1_0000,
            "Cold boot Caliptra fatal error before mailbox was ready"
        ),
        (
            ROM_COLD_BOOT_START_RI_DOWNLOAD_ERROR,
            0x1_0001,
            "Cold boot failed to start recovery interface download"
        ),
        (
            ROM_COLD_BOOT_FINISH_RI_DOWNLOAD_ERROR,
            0x1_0002,
            "Cold boot failed to finish recovery interface download"
        ),
        (
            ROM_COLD_BOOT_LOAD_IMAGE_ERROR,
            0x1_0003,
            "Cold boot failed to load firmware image"
        ),
        (
            ROM_COLD_BOOT_HEADER_VERIFY_ERROR,
            0x1_0004,
            "Cold boot failed to verify firmware image header"
        ),
        (
            ROM_COLD_BOOT_INVALID_FIRMWARE,
            0x1_0005,
            "Cold boot firmware is invalid"
        ),
        (
            ROM_COLD_BOOT_RESET_ERROR,
            0x1_0006,
            "Cold boot reset to firmware boot error"
        ),
        (
            ROM_COLD_BOOT_FIELD_ENTROPY_PROG_START,
            0x1_0007,
            "Cold boot failed to start field entropy program"
        ),
        (
            ROM_COLD_BOOT_FIELD_ENTROPY_PROG_FINISH,
            0x1_0008,
            "Cold boot failed to finish field entropy program"
        ),
        (
            ROM_FW_BOOT_INVALID_FIRMWARE,
            0x1_0009,
            "Firmware boot reset invalid firmware"
        ),
        (
            ROM_FW_HITLESS_UPDATE_CLEAR_MB_ERROR,
            0x1_000a,
            "Hitless update failed to clear the Caliptra mailbox"
        ),
        (
            ROM_WARM_BOOT_INVALID_FIRMWARE,
            0x1_000b,
            "Warm boot invalid firmware"
        ),
        (ROM_WARM_BOOT_RESET_ERROR, 0x1000c, "Warm boot reset error"),
        (
            ROM_ROM_INVALID_RESET_REASON,
            0x1_000d,
            "Invalid reset reason"
        ),
        (
            ROM_COLD_BOOT_DOT_ERROR,
            0x1_000e,
            "Device Ownership Transfer generic error"
        ),
        (
            ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR,
            0x1_000f,
            "Device Ownership Transfer corrupt blob"
        ),
        (
            ROM_LC_TRANSITION_ERROR,
            0x2_0000,
            "Lifecycle transition error"
        ),
        (ROM_LC_TOKEN_ERROR, 0x2_0001, "Lifecycle token error"),
        (ROM_LC_OTP_ERROR, 0x2_0002, "Lifecycle OTP error"),
        (
            ROM_LC_FLASH_RMA_ERROR,
            0x2_0003,
            "Lifecycle flash RMA error"
        ),
        (
            ROM_LC_TRANSITION_COUNT_ERROR,
            0x2_0004,
            "Lifecycle transition count error"
        ),
        (ROM_LC_STATE_ERROR, 0x2_0005, "Lifecycle state error"),
        (
            ROM_LC_BUS_INTEG_ERROR,
            0x2_0006,
            "Lifecycle bus integrity error"
        ),
        (
            ROM_LC_OTP_PARTITION_ERROR,
            0x2_0007,
            "Lifecycle OTP partition error"
        ),
        (
            ROM_OTP_INIT_STATUS_ERROR,
            0x3_0000,
            "OTP controller status error during initialization"
        ),
        (
            ROM_OTP_INIT_NOT_IDLE,
            0x3_0001,
            "OTP controller not idle during initialization"
        ),
        (
            ROM_OTP_INVALID_DATA_ERROR,
            0x3_0002,
            "OTP invalid data error"
        ),
        (ROM_OTP_READ_ERROR, 0x3_0003, "Failed to read from OTP"),
        (
            ROM_OTP_WRITE_DWORD_ERROR,
            0x3_0004,
            "Failed to write dword to OTP"
        ),
        (
            ROM_OTP_WRITE_WORD_ERROR,
            0x3_0005,
            "Failed to write word to OTP"
        ),
        (
            ROM_OTP_FINALIZE_DIGEST_ERROR,
            0x3_0006,
            "Failed to finalize digest"
        ),
        (
            ROM_UNSUPPORTED_FUSE_LAYOUT,
            0x3_0007,
            "Unsupported layout for fuse extraction"
        ),
        (
            ROM_FUSE_LAYOUT_TOO_LARGE,
            0x3_0008,
            "Fuse layout too large for data"
        ),
        (
            ROM_FUSE_LAYOUT_ONE_HOT_RESULT_SHOULD_BE_SINGLE_U32,
            0x3_0009,
            "One-hot encoded output should be single u32"
        ),
        (
            ROM_FUSE_VALUE_TOO_LARGE,
            0x3_000a,
            "Fuse value too large for layout"
        ),
        (
            ROM_I3C_CONFIG_RING_HEADER_ERROR,
            0x4_0000,
            "I3C config ring header error"
        ),
        (
            ROM_I3C_CONFIG_STDBY_CTRL_MODE_ERROR,
            0x4_0001,
            "I3C config standby controller mode error"
        ),
        (
            SOC_FMC_KEY_MANIFEST_SVN_LEN_MISMATCH,
            0x5_0000,
            "SOC FMC key manifest SVN length mismatch"
        ),
        (
            ROM_SOC_KEY_MANIFEST_PK_HASH_LEN_MISMATCH,
            0x5_0001,
            "SOC key manifest PK hash length mismatch"
        ),
        (
            ROM_SOC_RT_SVN_LEN_MISMATCH,
            0x5_0002,
            "Runtime SVN length mismatch"
        ),
        (
            ROM_SOC_MANIFEST_SVN_LEN_MISMATCH,
            0x5_0003,
            "SOC Manifest SVN length mismatch"
        ),
        (
            SOC_MANIFEST_MAX_SVN_LEN_MISMATCH,
            0x5_0004,
            "SOC Manifest Max SVN length mismatch"
        ),
        (
            ROM_SOC_MANUF_DEBUG_UNLOCK_TOKEN_LEN_MISMATCH,
            0x5_0005,
            "SOC manuf debug unlock token length mismatch"
        ),
        (
            ROM_SOC_STEPPING_ID_LEN_MISMATCH,
            0x5_0006,
            "SOC stepping ID length mismatch"
        ),
        (
            ROM_SOC_ANTI_ROLLBACK_DISABLE_LEN_MISMATCH,
            0x5_0007,
            "SOC stepping ID length mismatch"
        ),
        (
            ROM_SOC_IDEVID_CERT_ATTR_LEN_MISMATCH,
            0x5_0008,
            "SOC IDevID Cert Attr length mismatch"
        ),
        (
            ROM_SOC_IDEVID_MANUF_HSM_ID_LEN_MISMATCH,
            0x5_0009,
            "SOC IDevID Manuf HSM ID length mismatch"
        ),
        (
            ROM_SOC_PROD_DEBUG_UNLOCK_PKS_HASH_LEN_MISMATCH,
            0x5_000A,
            "SOC Prod Debug Unlock PKS Hash length mismatch"
        ),
        (
            ROM_SOC_CALIPTRA_FATAL_ERROR_BEFORE_FW_READY,
            0x5_000B,
            "SOC Caliptra fatal error before firmware ready"
        ),
        (
            ROM_SOC_MBOX_USER_OUT_OF_RANGE,
            0x5_000C,
            "SOC tried to set an Mbox user out of range"
        ),
        (
            ROM_SOC_MBOX_USER_LOCK_OUT_OF_RANGE,
            0x5_000D,
            "SOC tried to lock an Mbox user out of range"
        ),
        (
            ROM_SOC_UDS_SEED_LEN_MISMATCH,
            0x5_000E,
            "SOC UDS seed length mismatch"
        ),
        (
            ROM_SOC_FIELD_ENTROPY_LEN_MISMATCH,
            0x5_000F,
            "SOC field entropy length mismatch"
        ),
        (
            GENERIC_EXCEPTION,
            0xF_0000,
            "Machine level exception was encountered during ROM execution"
        ),
    ];
}

impl From<core::num::NonZeroU32> for crate::McuError {
    fn from(val: core::num::NonZeroU32) -> Self {
        crate::McuError(val)
    }
}

impl From<McuError> for core::num::NonZeroU32 {
    fn from(val: McuError) -> Self {
        val.0
    }
}

impl From<McuError> for u32 {
    fn from(val: McuError) -> Self {
        core::num::NonZeroU32::from(val).get()
    }
}

impl TryFrom<u32> for McuError {
    type Error = TryFromIntError;
    fn try_from(val: u32) -> Result<Self, TryFromIntError> {
        match NonZeroU32::try_from(val) {
            Ok(val) => Ok(McuError(val)),
            Err(err) => Err(err),
        }
    }
}

pub type McuResult<T> = Result<T, McuError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_try_from() {
        assert!(McuError::try_from(0).is_err());
        assert_eq!(
            Ok(McuError::ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY),
            McuError::try_from(0x1_0000)
        );
    }

    #[test]
    fn test_error_constants_uniqueness() {
        let constants = McuError::all_constants();
        let mut error_values = HashSet::new();
        let mut duplicates = Vec::new();

        for (name, value) in constants {
            if !error_values.insert(value) {
                duplicates.push((name, value));
            }
        }

        assert!(
            duplicates.is_empty(),
            "Found duplicate error codes: {:?}",
            duplicates
        );
    }
}
