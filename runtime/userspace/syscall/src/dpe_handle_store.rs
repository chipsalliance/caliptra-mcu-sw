// Licensed under the Apache-2.0 license

//! Userspace interface to the DPE Handle Storage capsule.
//!
//! All operations are **synchronous**: each method sets up an allow buffer,
//! issues the kernel command, reads the result, and unallows the buffer before
//! returning.  No async/subscribe is used.
//!
//! ## Example
//!
//! ```rust,ignore
//! let store = DpeHandleStore::new(DPE_HANDLE_STORE_DRIVER_NUM);
//! store.exists()?;
//!
//! // Write a record
//! let record = DpeHandleRecord {
//!     fw_id: 0x1,
//!     parent_fw_id: None,
//!     context_handle: [0u8; 16],
//!     tci_tag: 0,
//!     flags: DpeHandleRecordFlags { valid: true, attestation_target: false },
//! };
//! store.write_record(record.fw_id, &record)?;
//!
//! // Read it back
//! let mut out = DpeHandleRecord::default();
//! store.read_record(0x1, &mut out)?;
//! ```

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{return_variant, syscall_class, ErrorCode, Syscalls};
use core::marker::PhantomData;

/// Driver number for the DPE Handle Storage capsule.
pub const DPE_HANDLE_STORE_DRIVER_NUM: u32 = 0x8000_0020;

/// Serialized size of a [`DpeHandleRecord`] in the allow buffer.
pub const DPE_HANDLE_RECORD_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Flags stored inside a [`DpeHandleRecord`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpeHandleRecordFlags {
    pub valid: bool,
    pub attestation_target: bool,
}

impl DpeHandleRecordFlags {
    fn from_byte(b: u8) -> Self {
        Self {
            valid: b & (1 << 0) != 0,
            attestation_target: b & (1 << 1) != 0,
        }
    }

    fn to_byte(self) -> u8 {
        (self.valid as u8) | ((self.attestation_target as u8) << 1)
    }
}

/// A DPE context handle record as seen by userspace.
///
/// Serialization matches the kernel's 32-byte SRAM layout exactly so that the
/// same bytes can be passed through the allow buffer without translation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpeHandleRecord {
    pub fw_id: u32,
    /// `None` is serialized as `0xFFFF_FFFF`.
    pub parent_fw_id: Option<u32>,
    pub context_handle: [u8; 16],
    pub tci_tag: u32,
    pub flags: DpeHandleRecordFlags,
}

impl DpeHandleRecord {
    /// Deserialize a `DpeHandleRecord` from the 32-byte wire format.
    pub fn from_bytes(b: &[u8; DPE_HANDLE_RECORD_SIZE]) -> Self {
        let fw_id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let raw_parent = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let parent_fw_id = if raw_parent == 0xFFFF_FFFF {
            None
        } else {
            Some(raw_parent)
        };
        let mut context_handle = [0u8; 16];
        context_handle.copy_from_slice(&b[8..24]);
        let tci_tag = u32::from_le_bytes([b[24], b[25], b[26], b[27]]);
        let flags = DpeHandleRecordFlags::from_byte(b[28]);
        Self {
            fw_id,
            parent_fw_id,
            context_handle,
            tci_tag,
            flags,
        }
    }

    /// Serialize a `DpeHandleRecord` into the 32-byte wire format.
    pub fn to_bytes(&self) -> [u8; DPE_HANDLE_RECORD_SIZE] {
        let mut b = [0u8; DPE_HANDLE_RECORD_SIZE];
        b[0..4].copy_from_slice(&self.fw_id.to_le_bytes());
        let raw_parent = self.parent_fw_id.unwrap_or(0xFFFF_FFFF);
        b[4..8].copy_from_slice(&raw_parent.to_le_bytes());
        b[8..24].copy_from_slice(&self.context_handle);
        b[24..28].copy_from_slice(&self.tci_tag.to_le_bytes());
        b[28] = self.flags.to_byte();
        // b[29..32] remain zero (padding)
        b
    }
}

// ---------------------------------------------------------------------------
// Syscall client
// ---------------------------------------------------------------------------

/// Userspace interface to the DPE Handle Storage capsule.
pub struct DpeHandleStore<S: Syscalls = DefaultSyscalls> {
    _syscalls: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> DpeHandleStore<S> {
    pub fn new(driver_num: u32) -> Self {
        Self {
            _syscalls: PhantomData,
            driver_num,
        }
    }

    /// Check that the kernel capsule is present (command 0).
    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::EXISTS, 0, 0).to_result()
    }

    /// Read the record for `fw_id` into `out`.
    pub fn read_record(&self, fw_id: u32, out: &mut DpeHandleRecord) -> Result<(), ErrorCode> {
        let mut buf = [0u8; DPE_HANDLE_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_RECORD, fw_id, &mut buf)?;
        *out = DpeHandleRecord::from_bytes(&buf);
        Ok(())
    }

    /// Write `record` as the entry for `fw_id`.  Creates a new slot if `fw_id`
    /// is not yet present; overwrites the existing slot otherwise.
    pub fn write_record(&self, fw_id: u32, record: &DpeHandleRecord) -> Result<(), ErrorCode> {
        let buf = record.to_bytes();
        allow_ro_command_unallow::<S>(self.driver_num, cmd::WRITE_RECORD, fw_id, &buf)
    }

    /// Clear all records and reset the attestation target marker.
    pub fn clear_records(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::CLEAR_RECORDS, 0, 0).to_result()
    }

    /// Read the last valid (leaf) DPE record into `out`.
    pub fn read_leaf_record(&self, out: &mut DpeHandleRecord) -> Result<(), ErrorCode> {
        let mut buf = [0u8; DPE_HANDLE_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_LEAF_RECORD, 0, &mut buf)?;
        *out = DpeHandleRecord::from_bytes(&buf);
        Ok(())
    }

    /// Mark `fw_id` as the attestation target.  The record must already exist.
    pub fn mark_attestation_target(&self, fw_id: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::MARK_ATTESTATION_TARGET, fw_id, 0).to_result()
    }

    /// Read the attestation target record into `out`.
    pub fn read_attestation_target(&self, out: &mut DpeHandleRecord) -> Result<(), ErrorCode> {
        let mut buf = [0u8; DPE_HANDLE_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_ATTESTATION_TARGET, 0, &mut buf)?;
        *out = DpeHandleRecord::from_bytes(&buf);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Synchronous allow helpers
// ---------------------------------------------------------------------------

/// Allow an RW buffer, issue a synchronous command, then unallow.
///
/// This follows the same raw-syscall pattern used by `TockSubscribe` for
/// runtime driver/buffer numbers.  The command is synchronous (no upcall), so
/// the kernel finishes reading/writing the buffer before returning the command
/// result.
fn allow_rw_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd_num: u32,
    arg1: u32,
    buf: &mut [u8],
) -> Result<(), ErrorCode> {
    // Allow the buffer.
    // Safety: `buf` is a valid Rust slice that outlives this function.  The
    // kernel command is synchronous, so the kernel will not access the buffer
    // after `command` returns.
    let allow_result = unsafe {
        S::syscall4::<{ syscall_class::ALLOW_RW }>([
            driver_num.into(),
            (rw_allow::OUTPUT as u32).into(),
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

    // Issue the synchronous command.
    let cmd_result = S::command(driver_num, cmd_num, arg1, 0).to_result::<(), ErrorCode>();

    // Always unallow, even on command failure.
    S::unallow_rw(driver_num, rw_allow::OUTPUT as u32);

    cmd_result
}

/// Allow a RO buffer, issue a synchronous command, then unallow.
fn allow_ro_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd_num: u32,
    arg1: u32,
    buf: &[u8],
) -> Result<(), ErrorCode> {
    // Safety: same reasoning as `allow_rw_command_unallow`.
    let allow_result = unsafe {
        S::syscall4::<{ syscall_class::ALLOW_RO }>([
            driver_num.into(),
            (ro_allow::INPUT as u32).into(),
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

    let cmd_result = S::command(driver_num, cmd_num, arg1, 0).to_result::<(), ErrorCode>();

    S::unallow_ro(driver_num, ro_allow::INPUT as u32);

    cmd_result
}

// ---------------------------------------------------------------------------
// Command / allow numbers (must match kernel capsule)
// ---------------------------------------------------------------------------

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const READ_RECORD: u32 = 1;
    pub const WRITE_RECORD: u32 = 2;
    pub const CLEAR_RECORDS: u32 = 3;
    pub const READ_LEAF_RECORD: u32 = 4;
    pub const MARK_ATTESTATION_TARGET: u32 = 5;
    pub const READ_ATTESTATION_TARGET: u32 = 6;
}

mod rw_allow {
    pub const OUTPUT: usize = 0;
}

mod ro_allow {
    pub const INPUT: usize = 0;
}
