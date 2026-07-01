// Licensed under the Apache-2.0 license

//! Userspace interface to the DPE Handle Storage capsule.

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{return_variant, syscall_class, ErrorCode, Syscalls};
use core::marker::PhantomData;

pub const DPE_HANDLE_STORE_DRIVER_NUM: u32 = 0x8000_0020;
pub const DPE_HANDLE_RECORD_SIZE: usize = 32;
pub const POLICY_DIGEST_SIZE: usize = 48;

// ---------------------------------------------------------------------------
// Record type
// ---------------------------------------------------------------------------

/// A DPE context handle record as seen by userspace.
///
/// The `flags` byte (offset 28 in the wire format) is **reserved** and not
/// interpreted by the kernel capsule.  Callers may store implementation-
/// specific data there; it is passed through verbatim on read/write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpeHandleRecord {
    pub fw_id: u32,
    /// `None` is serialized as `0xFFFF_FFFF`.
    pub parent_fw_id: Option<u32>,
    pub context_handle: [u8; 16],
    pub tci_tag: u32,
    /// Reserved; not interpreted by the kernel capsule.
    pub flags: u8,
}

impl DpeHandleRecord {
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
        let flags = b[28];
        Self {
            fw_id,
            parent_fw_id,
            context_handle,
            tci_tag,
            flags,
        }
    }

    pub fn to_bytes(&self) -> [u8; DPE_HANDLE_RECORD_SIZE] {
        let mut b = [0u8; DPE_HANDLE_RECORD_SIZE];
        b[0..4].copy_from_slice(&self.fw_id.to_le_bytes());
        let raw_parent = self.parent_fw_id.unwrap_or(0xFFFF_FFFF);
        b[4..8].copy_from_slice(&raw_parent.to_le_bytes());
        b[8..24].copy_from_slice(&self.context_handle);
        b[24..28].copy_from_slice(&self.tci_tag.to_le_bytes());
        b[28] = self.flags;
        b
    }
}

// ---------------------------------------------------------------------------
// Syscall client
// ---------------------------------------------------------------------------

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

    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::EXISTS, 0, 0).to_result()
    }

    pub fn read_record(&self, fw_id: u32, out: &mut DpeHandleRecord) -> Result<(), ErrorCode> {
        let mut buf = [0u8; DPE_HANDLE_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_RECORD, fw_id, &mut buf)?;
        *out = DpeHandleRecord::from_bytes(&buf);
        Ok(())
    }

    pub fn write_record(&self, fw_id: u32, record: &DpeHandleRecord) -> Result<(), ErrorCode> {
        let buf = record.to_bytes();
        allow_ro_command_unallow::<S>(self.driver_num, cmd::WRITE_RECORD, fw_id, &buf)
    }

    /// Initialize the store on cold boot: write header, store `policy_digest`,
    /// reset record count, and zero all record slots.
    pub fn initialize_store(
        &self,
        policy_digest: &[u8; POLICY_DIGEST_SIZE],
    ) -> Result<(), ErrorCode> {
        allow_ro_command_unallow::<S>(self.driver_num, cmd::INITIALIZE_STORE, 0, policy_digest)
    }

    pub fn read_leaf_record(&self, out: &mut DpeHandleRecord) -> Result<(), ErrorCode> {
        let mut buf = [0u8; DPE_HANDLE_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_LEAF_RECORD, 0, &mut buf)?;
        *out = DpeHandleRecord::from_bytes(&buf);
        Ok(())
    }

    pub fn mark_attestation_target(&self, fw_id: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::MARK_ATTESTATION_TARGET, fw_id, 0).to_result()
    }

    pub fn read_attestation_target(&self, out: &mut DpeHandleRecord) -> Result<(), ErrorCode> {
        let mut buf = [0u8; DPE_HANDLE_RECORD_SIZE];
        allow_rw_command_unallow::<S>(self.driver_num, cmd::READ_ATTESTATION_TARGET, 0, &mut buf)?;
        *out = DpeHandleRecord::from_bytes(&buf);
        Ok(())
    }

    /// Validate the store on hitless-update boot: check header integrity and
    /// that the stored policy digest matches `policy_digest`.
    pub fn validate_store(
        &self,
        policy_digest: &[u8; POLICY_DIGEST_SIZE],
    ) -> Result<(), ErrorCode> {
        allow_ro_command_unallow::<S>(self.driver_num, cmd::VALIDATE_STORE, 0, policy_digest)
    }
}

// ---------------------------------------------------------------------------
// Synchronous allow helpers
// ---------------------------------------------------------------------------

fn allow_rw_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd_num: u32,
    arg1: u32,
    buf: &mut [u8],
) -> Result<(), ErrorCode> {
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
    let cmd_result = S::command(driver_num, cmd_num, arg1, 0).to_result::<(), ErrorCode>();
    S::unallow_rw(driver_num, rw_allow::OUTPUT as u32);
    cmd_result
}

fn allow_ro_command_unallow<S: Syscalls>(
    driver_num: u32,
    cmd_num: u32,
    arg1: u32,
    buf: &[u8],
) -> Result<(), ErrorCode> {
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

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const READ_RECORD: u32 = 1;
    pub const WRITE_RECORD: u32 = 2;
    pub const INITIALIZE_STORE: u32 = 3;
    pub const READ_LEAF_RECORD: u32 = 4;
    pub const MARK_ATTESTATION_TARGET: u32 = 5;
    pub const READ_ATTESTATION_TARGET: u32 = 6;
    pub const VALIDATE_STORE: u32 = 7;
}

mod rw_allow {
    pub const OUTPUT: usize = 0;
}

mod ro_allow {
    pub const INPUT: usize = 0;
}
