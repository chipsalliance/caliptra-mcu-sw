// Licensed under the Apache-2.0 license

//! Userspace API for the Software PCR Store.
//!
//! ## Command contract
//!
//! | # | Name               | Arg0  | Allow         |
//! |---|--------------------|-------|---------------|
//! | 0 | EXISTS             | —     | —             |
//! | 1 | READ_MEASUREMENT   | fw_id | RW 0 (output) |
//! | 2 | CREATE_MEASUREMENT | fw_id | RO 0 (input)  |
//! | 3 | UPDATE_MEASUREMENT | fw_id | RO 0 (input)  |
//! | 4 | INITIALIZE_STORE   | —     | —             |
//! | 5 | VALIDATE_STORE     | —     | —             |
//!
//! SHA-384 measurement computation is performed entirely in userspace using
//! the Caliptra SHA mailbox APIs.  The capsule only stores and retrieves
//! records; it does not compute digests.

use caliptra_mcu_libtock_platform::{return_variant, syscall_class, ErrorCode, Syscalls};

use crate::DefaultSyscalls;

/// Driver number for the Software PCR Store kernel capsule.
pub const SOFT_PCR_STORE_DRIVER_NUM: u32 = 0x8000_0021;

/// Serialized size of one `MeasurementRecord` (112 bytes).
pub const MEASUREMENT_RECORD_SIZE: usize = 112;

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const READ_MEASUREMENT: u32 = 1;
    pub const CREATE_MEASUREMENT: u32 = 2;
    pub const UPDATE_MEASUREMENT: u32 = 3;
    pub const INITIALIZE_STORE: u32 = 4;
    pub const VALIDATE_STORE: u32 = 5;
}

/// A `fw_id`-keyed Software PCR measurement record.
///
/// Serialized layout (112 bytes, little-endian):
///
/// ```text
/// offset   0: fw_id          u32 LE
/// offset   4: current_digest [u8; 48]
/// offset  52: journey_digest [u8; 48]
/// offset 100: svn            u32 LE
/// offset 104: version        u32 LE
/// offset 108: reserved       [u8; 4]
/// ```
#[derive(Clone, Debug)]
pub struct MeasurementRecord {
    pub fw_id: u32,
    pub current_digest: [u8; 48],
    pub journey_digest: [u8; 48],
    pub svn: u32,
    pub version: u32,
    pub reserved: [u8; 4],
}

impl Default for MeasurementRecord {
    fn default() -> Self {
        Self {
            fw_id: 0,
            current_digest: [0u8; 48],
            journey_digest: [0u8; 48],
            svn: 0,
            version: 0,
            reserved: [0u8; 4],
        }
    }
}

impl MeasurementRecord {
    pub fn serialize(&self) -> [u8; MEASUREMENT_RECORD_SIZE] {
        let mut out = [0u8; MEASUREMENT_RECORD_SIZE];
        out[0..4].copy_from_slice(&self.fw_id.to_le_bytes());
        out[4..52].copy_from_slice(&self.current_digest);
        out[52..100].copy_from_slice(&self.journey_digest);
        out[100..104].copy_from_slice(&self.svn.to_le_bytes());
        out[104..108].copy_from_slice(&self.version.to_le_bytes());
        // reserved stays zero
        out
    }

    pub fn deserialize(bytes: &[u8; MEASUREMENT_RECORD_SIZE]) -> Self {
        let fw_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut current_digest = [0u8; 48];
        current_digest.copy_from_slice(&bytes[4..52]);
        let mut journey_digest = [0u8; 48];
        journey_digest.copy_from_slice(&bytes[52..100]);
        let svn = u32::from_le_bytes([bytes[100], bytes[101], bytes[102], bytes[103]]);
        let version = u32::from_le_bytes([bytes[104], bytes[105], bytes[106], bytes[107]]);
        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&bytes[108..112]);
        Self {
            fw_id,
            current_digest,
            journey_digest,
            svn,
            version,
            reserved,
        }
    }
}

/// Synchronous interface to the Software PCR Store capsule.
pub struct SoftwarePcrStore<S: Syscalls = DefaultSyscalls> {
    _syscalls: core::marker::PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> SoftwarePcrStore<S> {
    pub fn new(driver_num: u32) -> Self {
        Self {
            _syscalls: core::marker::PhantomData,
            driver_num,
        }
    }

    /// Verify the capsule is present.
    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::EXISTS, 0, 0).to_result()
    }

    /// Cold-boot initialization: write a fresh header and zero all record slots.
    pub fn initialize_store(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::INITIALIZE_STORE, 0, 0).to_result()
    }

    /// Hitless-update validation: verify header magic/version/sizes and
    /// `record_count <= record_capacity`.
    pub fn validate_store(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::VALIDATE_STORE, 0, 0).to_result()
    }

    /// Read the measurement record for `fw_id`.
    ///
    /// Returns `ErrorCode::Fail` if `fw_id` does not exist.
    pub fn read_measurement(
        &self,
        fw_id: u32,
        out: &mut MeasurementRecord,
    ) -> Result<(), ErrorCode> {
        let mut buf = [0u8; MEASUREMENT_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_MEASUREMENT, fw_id, &mut buf)?;
        *out = MeasurementRecord::deserialize(&buf);
        Ok(())
    }

    /// Create a new record for `fw_id`.
    ///
    /// Returns `ErrorCode::Already` if `fw_id` already exists.
    /// Returns `ErrorCode::NoMem` if capacity is exhausted.
    pub fn create_measurement(
        &self,
        fw_id: u32,
        record: &MeasurementRecord,
    ) -> Result<(), ErrorCode> {
        let buf = record.serialize();
        allow_ro_command_unallow::<S>(self.driver_num, cmd::CREATE_MEASUREMENT, fw_id, &buf)
    }

    /// Update the existing record for `fw_id`.
    ///
    /// Returns `ErrorCode::Fail` if `fw_id` does not exist.
    pub fn update_measurement(
        &self,
        fw_id: u32,
        record: &MeasurementRecord,
    ) -> Result<(), ErrorCode> {
        let buf = record.serialize();
        allow_ro_command_unallow::<S>(self.driver_num, cmd::UPDATE_MEASUREMENT, fw_id, &buf)
    }
}

fn allow_rw_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd: u32,
    arg0: u32,
    buf: &mut [u8],
) -> Result<(), ErrorCode> {
    let allow_result = unsafe {
        S::syscall4::<{ syscall_class::ALLOW_RW }>([
            driver_num.into(),
            0u32.into(),
            buf.as_mut_ptr().into(),
            buf.len().into(),
        ])
    };
    let rv: return_variant::ReturnVariant = allow_result[0].as_u32().into();
    if rv == return_variant::FAILURE_2_U32 {
        return Err(allow_result[1]
            .as_u32()
            .try_into()
            .unwrap_or(ErrorCode::Fail));
    }
    let result = S::command(driver_num, cmd, arg0, 0).to_result::<(), ErrorCode>();
    S::unallow_rw(driver_num, 0);
    result
}

fn allow_ro_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd: u32,
    arg0: u32,
    buf: &[u8],
) -> Result<(), ErrorCode> {
    let allow_result = unsafe {
        S::syscall4::<{ syscall_class::ALLOW_RO }>([
            driver_num.into(),
            0u32.into(),
            buf.as_ptr().into(),
            buf.len().into(),
        ])
    };
    let rv: return_variant::ReturnVariant = allow_result[0].as_u32().into();
    if rv == return_variant::FAILURE_2_U32 {
        return Err(allow_result[1]
            .as_u32()
            .try_into()
            .unwrap_or(ErrorCode::Fail));
    }
    let result = S::command(driver_num, cmd, arg0, 0).to_result::<(), ErrorCode>();
    S::unallow_ro(driver_num, 0);
    result
}
