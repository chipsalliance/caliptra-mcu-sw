// Licensed under the Apache-2.0 license

//! DPE Handle Storage capsule: stores `fw_id`-keyed DPE context handle records
//! for MCU Runtime and SoC TCB components in a reserved SRAM subregion.
//!
//! The capsule takes exclusive ownership of a `&'static mut [u8]` slice that
//! covers the DPE Handle Storage subregion of the measurement-store SRAM
//! reservation.  All operations are **synchronous**; no upcalls are used.
//!
//! ## Driver number
//!
//! `0x8000_0020`
//!
//! ## SRAM layout
//!
//! ```text
//! offset 0 : record_count           u16 LE
//! offset 2 : _pad                   u16
//! offset 4 : attestation_target_fw_id  u32 LE  (0xFFFF_FFFF = none)
//! offset 8 : records[0..capacity]   DPE_HANDLE_RECORD_SIZE bytes each
//! ```
//!
//! ## Record layout (`DPE_HANDLE_RECORD_SIZE` = 32 bytes)
//!
//! ```text
//! offset  0 : fw_id            u32 LE
//! offset  4 : parent_fw_id     u32 LE  (0xFFFF_FFFF = None)
//! offset  8 : context_handle   [u8; 16]
//! offset 24 : tci_tag          u32 LE
//! offset 28 : flags            u8  (bit 0 = valid, bit 1 = attestation_target)
//! offset 29 : _pad             [u8; 3]
//! ```
//!
//! ## Syscalls (all synchronous)
//!
//! | Command | Name                    | Arg1   | Arg2     | Allow           |
//! |---------|-------------------------|--------|----------|-----------------|
//! | 0       | EXISTS                  | —      | —        | —               |
//! | 1       | READ_RECORD             | fw_id  | reserved | RW 0 (output)   |
//! | 2       | WRITE_RECORD            | fw_id  | reserved | RO 0 (input)    |
//! | 3       | CLEAR_RECORDS           | —      | —        | —               |
//! | 4       | READ_LEAF_RECORD        | —      | —        | RW 0 (output)   |
//! | 5       | MARK_ATTESTATION_TARGET | fw_id  | reserved | —               |
//! | 6       | READ_ATTESTATION_TARGET | —      | —        | RW 0 (output)   |
//!
//! **Read-Write Allow 0** — output buffer for READ_RECORD / READ_LEAF_RECORD /
//! READ_ATTESTATION_TARGET; must be at least `DPE_HANDLE_RECORD_SIZE` bytes.
//!
//! **Read-Only Allow 0** — input buffer for WRITE_RECORD; must be at least
//! `DPE_HANDLE_RECORD_SIZE` bytes.

use core::cell::RefCell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// Proposed driver number for the DPE Handle Storage capsule.
pub const DRIVER_NUM: usize = 0x8000_0020;

/// Serialized size of one `DpeHandleRecord` in SRAM and in allow buffers.
pub const DPE_HANDLE_RECORD_SIZE: usize = 32;

/// Sentinel used for `parent_fw_id` = None and "no attestation target".
const SENTINEL_NONE: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Metadata offsets within the SRAM region
// ---------------------------------------------------------------------------

/// Byte offset of `record_count` (u16 LE).
const META_RECORD_COUNT: usize = 0;
/// Byte offset of `attestation_target_fw_id` (u32 LE).
const META_ATTEST_TARGET: usize = 4;
/// Total size of the metadata header that precedes the record array.
const META_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Per-record field offsets within a DPE_HANDLE_RECORD_SIZE-byte slot
// ---------------------------------------------------------------------------

const REC_FW_ID: usize = 0;
const _REC_PARENT_FW_ID: usize = 4;
const _REC_CONTEXT_HANDLE: usize = 8; // 16 bytes
const _REC_TCI_TAG: usize = 24;
const REC_FLAGS: usize = 28;
// [29..32] _pad

const FLAG_VALID: u8 = 1 << 0;
// const FLAG_ATTESTATION_TARGET: u8 = 1 << 1;  // stored in record but not
// used for lookup; attestation target tracked via metadata field

// ---------------------------------------------------------------------------
// Allow buffer numbering
// ---------------------------------------------------------------------------

mod ro_allow {
    /// Input buffer for WRITE_RECORD (one serialized `DpeHandleRecord`).
    pub const INPUT: usize = 0;
    pub const COUNT: u8 = 1;
}

mod rw_allow {
    /// Output buffer for READ_RECORD / READ_LEAF_RECORD / READ_ATTESTATION_TARGET.
    pub const OUTPUT: usize = 0;
    pub const COUNT: u8 = 1;
}

// ---------------------------------------------------------------------------
// Capsule
// ---------------------------------------------------------------------------

/// Per-process grant state (empty; no per-process data needed).
#[derive(Default)]
pub struct App {}

/// DPE Handle Storage capsule.
pub struct DpeHandleStore {
    driver_num: usize,
    /// Reserved SRAM subregion owned by this capsule.
    mem: RefCell<&'static mut [u8]>,
    apps: Grant<
        App,
        UpcallCount<0>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
}

impl DpeHandleStore {
    pub fn new(
        driver_num: usize,
        mem: &'static mut [u8],
        grant: Grant<
            App,
            UpcallCount<0>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self {
            driver_num,
            mem: RefCell::new(mem),
            apps: grant,
        }
    }

    // -----------------------------------------------------------------------
    // Metadata helpers
    // -----------------------------------------------------------------------

    fn record_capacity(&self) -> usize {
        let len = self.mem.borrow().len();
        if len > META_SIZE {
            (len - META_SIZE) / DPE_HANDLE_RECORD_SIZE
        } else {
            0
        }
    }

    fn record_count(&self) -> usize {
        let mem = self.mem.borrow();
        read_u16_le(&mem, META_RECORD_COUNT) as usize
    }

    fn set_record_count(&self, count: u16) {
        let mut mem = self.mem.borrow_mut();
        write_u16_le(&mut mem, META_RECORD_COUNT, count);
    }

    fn attestation_target_fw_id(&self) -> u32 {
        let mem = self.mem.borrow();
        read_u32_le(&mem, META_ATTEST_TARGET)
    }

    fn set_attestation_target_fw_id(&self, fw_id: u32) {
        let mut mem = self.mem.borrow_mut();
        write_u32_le(&mut mem, META_ATTEST_TARGET, fw_id);
    }

    // -----------------------------------------------------------------------
    // Record helpers
    // -----------------------------------------------------------------------

    fn record_offset(index: usize) -> usize {
        META_SIZE + index * DPE_HANDLE_RECORD_SIZE
    }

    /// Search the valid record array for `fw_id`.  Returns the slot index, or
    /// `None` if not found.
    fn find_record_index(&self, fw_id: u32) -> Option<usize> {
        let count = self.record_count();
        let mem = self.mem.borrow();
        for i in 0..count {
            let off = Self::record_offset(i);
            if mem[off + REC_FLAGS] & FLAG_VALID != 0 && read_u32_le(&mem, off + REC_FW_ID) == fw_id
            {
                return Some(i);
            }
        }
        None
    }

    /// Copy the 32-byte serialized record at `index` into the process output
    /// buffer `slice`.
    fn copy_record_to_slice(
        &self,
        index: usize,
        slice: &WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if slice.len() < DPE_HANDLE_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let mem = self.mem.borrow();
        let off = Self::record_offset(index);
        slice
            .get(0..DPE_HANDLE_RECORD_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_from_slice(&mem[off..off + DPE_HANDLE_RECORD_SIZE]);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Command implementations
    // -----------------------------------------------------------------------

    fn do_read_record(&self, fw_id: u32, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        let index = self.find_record_index(fw_id).ok_or(ErrorCode::FAIL)?;
        self.copy_record_to_slice(index, slice)
    }

    fn do_write_record(&self, fw_id: u32, slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        if slice.len() < DPE_HANDLE_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }

        // If a record for this fw_id already exists, overwrite it in-place.
        if let Some(index) = self.find_record_index(fw_id) {
            let mut mem = self.mem.borrow_mut();
            let off = Self::record_offset(index);
            slice
                .get(0..DPE_HANDLE_RECORD_SIZE)
                .ok_or(ErrorCode::SIZE)?
                .copy_to_slice(&mut mem[off..off + DPE_HANDLE_RECORD_SIZE]);
            // Stamp fw_id and ensure the valid flag is set.
            write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
            mem[off + REC_FLAGS] |= FLAG_VALID;
            return Ok(());
        }

        // Otherwise append a new record.
        let count = self.record_count();
        let capacity = self.record_capacity();
        if count >= capacity {
            return Err(ErrorCode::NOMEM);
        }

        let mut mem = self.mem.borrow_mut();
        let off = Self::record_offset(count);
        slice
            .get(0..DPE_HANDLE_RECORD_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_to_slice(&mut mem[off..off + DPE_HANDLE_RECORD_SIZE]);
        write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
        mem[off + REC_FLAGS] |= FLAG_VALID;
        drop(mem);

        self.set_record_count(count as u16 + 1);
        Ok(())
    }

    fn do_clear_records(&self) {
        let mut mem = self.mem.borrow_mut();

        // Zero the metadata header.
        for b in mem[..META_SIZE].iter_mut() {
            *b = 0;
        }
        // Write the sentinel for "no attestation target".
        write_u32_le(&mut mem, META_ATTEST_TARGET, SENTINEL_NONE);

        // Zero all record slots.
        let capacity = if mem.len() > META_SIZE {
            (mem.len() - META_SIZE) / DPE_HANDLE_RECORD_SIZE
        } else {
            0
        };
        for i in 0..capacity {
            let off = META_SIZE + i * DPE_HANDLE_RECORD_SIZE;
            for b in mem[off..off + DPE_HANDLE_RECORD_SIZE].iter_mut() {
                *b = 0;
            }
        }
    }

    fn do_read_leaf_record(&self, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        if slice.len() < DPE_HANDLE_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let count = self.record_count();
        if count == 0 {
            return Err(ErrorCode::FAIL);
        }
        // The leaf is the last valid record (highest index).
        let mem = self.mem.borrow();
        for i in (0..count).rev() {
            let off = Self::record_offset(i);
            if mem[off + REC_FLAGS] & FLAG_VALID != 0 {
                slice
                    .get(0..DPE_HANDLE_RECORD_SIZE)
                    .ok_or(ErrorCode::SIZE)?
                    .copy_from_slice(&mem[off..off + DPE_HANDLE_RECORD_SIZE]);
                return Ok(());
            }
        }
        Err(ErrorCode::FAIL)
    }

    fn do_mark_attestation_target(&self, fw_id: u32) -> Result<(), ErrorCode> {
        if self.find_record_index(fw_id).is_none() {
            return Err(ErrorCode::FAIL);
        }
        self.set_attestation_target_fw_id(fw_id);
        Ok(())
    }

    fn do_read_attestation_target(&self, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        if slice.len() < DPE_HANDLE_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let attest_fw_id = self.attestation_target_fw_id();
        if attest_fw_id == SENTINEL_NONE {
            return Err(ErrorCode::FAIL);
        }
        let index = self
            .find_record_index(attest_fw_id)
            .ok_or(ErrorCode::FAIL)?;
        self.copy_record_to_slice(index, slice)
    }
}

// ---------------------------------------------------------------------------
// SyscallDriver impl
// ---------------------------------------------------------------------------

impl SyscallDriver for DpeHandleStore {
    fn command(
        &self,
        cmd_num: usize,
        arg1: usize,
        _arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match cmd_num as u32 {
            cmd::EXISTS => CommandReturn::success(),

            cmd::READ_RECORD => {
                let fw_id = arg1 as u32;
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(rw_allow::OUTPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.mut_enter(|slice| self.do_read_record(fw_id, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::WRITE_RECORD => {
                let fw_id = arg1 as u32;
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| self.do_write_record(fw_id, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::CLEAR_RECORDS => {
                self.do_clear_records();
                CommandReturn::success()
            }

            cmd::READ_LEAF_RECORD => {
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(rw_allow::OUTPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.mut_enter(|slice| self.do_read_leaf_record(slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::MARK_ATTESTATION_TARGET => {
                let fw_id = arg1 as u32;
                match self.do_mark_attestation_target(fw_id) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            cmd::READ_ATTESTATION_TARGET => {
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(rw_allow::OUTPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.mut_enter(|slice| self.do_read_attestation_target(slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_u16_le(mem: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([mem[offset], mem[offset + 1]])
}

#[inline]
fn write_u16_le(mem: &mut [u8], offset: usize, val: u16) {
    let b = val.to_le_bytes();
    mem[offset] = b[0];
    mem[offset + 1] = b[1];
}

#[inline]
fn read_u32_le(mem: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        mem[offset],
        mem[offset + 1],
        mem[offset + 2],
        mem[offset + 3],
    ])
}

#[inline]
fn write_u32_le(mem: &mut [u8], offset: usize, val: u32) {
    let b = val.to_le_bytes();
    mem[offset] = b[0];
    mem[offset + 1] = b[1];
    mem[offset + 2] = b[2];
    mem[offset + 3] = b[3];
}

// ---------------------------------------------------------------------------
// Command numbers
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

// ---------------------------------------------------------------------------
// Driver number accessor (for board lookup table)
// ---------------------------------------------------------------------------

impl DpeHandleStore {
    pub fn get_driver_num(&self) -> usize {
        self.driver_num
    }
}
