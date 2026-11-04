// Licensed under the Apache-2.0 license

//! DPE Handle Storage capsule: stores `fw_id`-keyed DPE context handle records
//! for MCU Runtime and SoC TCB components in a reserved SRAM subregion.
//!
//! The capsule takes exclusive ownership of a `&'static mut [u8]` slice that
//! covers the DPE Handle Storage subregion of the measurement-store SRAM
//! reservation.  All operations are **synchronous**; no upcalls are used.
//!
//! ## Driver number: `0x8000_0020`
//!
//! ## SRAM layout
//!
//! ### Header (72 bytes) + variable Exported-CDI slots + records
//!
//! ```text
//! offset  0 : magic                     u32 LE  (0xD9E4_C7A1)
//! offset  4 : version                   u8      (2)
//! offset  5 : _pad                      u8
//! offset  6 : header_size               u16 LE  (72)
//! offset  8 : record_size               u16 LE  (DPE_HANDLE_RECORD_SIZE = 32)
//! offset 10 : record_capacity           u16 LE
//! offset 12 : record_count              u32 LE
//! offset 16 : attestation_target_fw_id  u32 LE  (0xFFFF_FFFF = none)
//! offset 20 : exported_cdi_capacity     u16 LE  (configured per board, default 1)
//! offset 22 : exported_cdi_count        u16 LE  (active slots in 0..=exported_cdi_capacity)
//! offset 24 : attestation_policy_digest [u8; 48]
//! offset 72 : exported_cdi_slots[0..exported_cdi_capacity] (EXPORTED_CDI_SLOT_SIZE = 36 B each)
//! offset 72 + exported_cdi_capacity * 36 : records[0..record_capacity] (32 B each)
//! ```
//!
//! Each exported-CDI slot (`EXPORTED_CDI_SLOT_SIZE` = 36 bytes) holds:
//!
//! ```text
//! offset  0 : fw_id                     u32 LE
//! offset  4 : exported_cdi_handle       [u8; 32]
//! ```
//!
//! Active exported-CDI slots occupy indices `0..exported_cdi_count`.
//! Records at indices `0..record_count` are all valid.  The `flags` byte
//! within each record (offset 28) is **reserved** — the capsule does not
//! interpret it for validity.  Record validity is determined solely by
//! position relative to `record_count`.
//!
//! ## Exported CDI Lifecycle
//!
//! Exported-CDI slots retain handles of exported Compound Device Identifiers
//! (CDIs) derived from DPE contexts (`fw_id`).
//!
//! ### Creation
//! - Derived via a DPE `DeriveContext` command with `EXPORT_CDI | CREATE_CERTIFICATE` flags.
//! - DPE generates the CDI in Caliptra KeyVault and returns a 32-byte handle.
//! - MCU Runtime stores `(fw_id, handle)` in this capsule via `WRITE_EXPORTED_CDI`.
//!
//! ### Usage
//! - Subsequent signing operations retrieve the handle for `fw_id` (or `0xFFFF_FFFF`
//!   for the first active slot) via `READ_EXPORTED_CDI` and pass it to Caliptra via
//!   `SIGN_WITH_EXPORTED_ECDSA` or `SIGN_WITH_EXPORTED_MLDSA`.
//!
//! ### Destruction, Invalidation & Revocation
//! - **Cold Boot / Power Cycle**: SRAM is cleared/reinitialized, destroying stored handles.
//!   Caliptra internal state is also lost, invalidating the CDI.
//! - **Caliptra Reset**: If Caliptra undergoes a cold reset, its internal state
//!   is lost, invalidating the CDI.
//! - **Revocation**: A handle can be explicitly revoked:
//!   - On the Caliptra side: By calling the Caliptra `REVOKE_EXPORTED_CDI_HANDLE` mailbox command.
//!     This is required before a new exported CDI can be derived when Caliptra's exported-CDI
//!     KeyVault slots (`EXPORTED_HANDLES_NUM`) are full.
//!   - On the MCU side: By calling `CLEAR_EXPORTED_CDI` to remove the slot for `fw_id`.
//!
//! ### Record layout (`DPE_HANDLE_RECORD_SIZE` = 32 bytes)
//!
//! ```text
//! offset  0 : fw_id            u32 LE
//! offset  4 : parent_fw_id     u32 LE  (0xFFFF_FFFF = None)
//! offset  8 : context_handle   [u8; 16]
//! offset 24 : tci_tag          u32 LE
//! offset 28 : flags            u8  (reserved)
//! offset 29 : _pad             [u8; 3]
//! ```
//!
//! ## Syscalls
//!
//! | Cmd | Name                    | Arg1  | Allow         |
//! |-----|-------------------------|-------|---------------|
//! | 0   | EXISTS                  | —     | —             |
//! | 1   | READ_RECORD             | fw_id | RW 0 (output) |
//! | 2   | WRITE_RECORD            | fw_id | RO 0 (input)  |
//! | 3   | INITIALIZE_STORE        | —     | RO 0 (digest) |
//! | 4   | READ_LEAF_RECORD        | —     | RW 0 (output) |
//! | 5   | MARK_ATTESTATION_TARGET | fw_id | —             |
//! | 6   | READ_ATTESTATION_TARGET | —     | RW 0 (output) |
//! | 7   | VALIDATE_STORE          | —     | RO 0 (digest) |
//! | 8   | READ_EXPORTED_CDI       | fw_id | RW 0 (output) |
//! | 9   | WRITE_EXPORTED_CDI      | fw_id | RO 0 (input)  |
//! | 10  | CLEAR_EXPORTED_CDI      | fw_id | —             |

use core::cell::RefCell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

pub const DRIVER_NUM: usize = 0x8000_0020;
pub const DPE_HANDLE_RECORD_SIZE: usize = 32;
pub const POLICY_DIGEST_SIZE: usize = 48;
pub const EXPORTED_CDI_SIZE: usize = 32;
pub const EXPORTED_CDI_SLOT_SIZE: usize = 36;
pub const DEFAULT_EXPORTED_CDI_CAPACITY: usize = 1;

const HEADER_MAGIC: u32 = 0xD9E4_C7A1;
const HEADER_VERSION: u8 = 2;
const SENTINEL_NONE: u32 = 0xFFFF_FFFF;

const META_MAGIC: usize = 0;
const META_VERSION: usize = 4;
const META_HEADER_SIZE: usize = 6;
const META_RECORD_SIZE: usize = 8;
const META_RECORD_CAPACITY: usize = 10;
const META_RECORD_COUNT: usize = 12;
const META_ATTEST_TARGET: usize = 16;
const META_EXPORTED_CDI_CAPACITY: usize = 20;
const META_EXPORTED_CDI_COUNT: usize = 22;
const META_POLICY_DIGEST: usize = 24;
const META_SIZE: usize = 72;

const SLOT_FW_ID: usize = 0;
const SLOT_HANDLE: usize = 4;

const REC_FW_ID: usize = 0;

mod ro_allow {
    pub const INPUT: usize = 0;
    pub const COUNT: u8 = 1;
}

mod rw_allow {
    pub const OUTPUT: usize = 0;
    pub const COUNT: u8 = 1;
}

#[derive(Default)]
pub struct App {}

pub struct DpeHandleStore {
    driver_num: usize,
    exported_cdi_capacity: usize,
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
        Self::with_exported_cdi_capacity(driver_num, mem, DEFAULT_EXPORTED_CDI_CAPACITY, grant)
    }

    pub fn with_exported_cdi_capacity(
        driver_num: usize,
        mem: &'static mut [u8],
        exported_cdi_capacity: usize,
        grant: Grant<
            App,
            UpcallCount<0>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self {
            driver_num,
            exported_cdi_capacity,
            mem: RefCell::new(mem),
            apps: grant,
        }
    }

    #[inline]
    fn records_base(&self) -> usize {
        META_SIZE + self.exported_cdi_capacity * EXPORTED_CDI_SLOT_SIZE
    }

    #[inline]
    fn exported_cdi_slot_offset(slot_index: usize) -> usize {
        META_SIZE + slot_index * EXPORTED_CDI_SLOT_SIZE
    }

    #[inline]
    fn record_capacity_in(&self, mem_len: usize) -> usize {
        let base = self.records_base();
        if mem_len > base {
            (mem_len - base) / DPE_HANDLE_RECORD_SIZE
        } else {
            0
        }
    }

    #[inline]
    fn record_offset_from(records_base: usize, index: usize) -> usize {
        records_base + index * DPE_HANDLE_RECORD_SIZE
    }

    /// Search `count` entries starting at `base` with `stride` for `fw_id` at offset 0.
    fn find_fw_id(
        mem: &[u8],
        base: usize,
        stride: usize,
        count: usize,
        fw_id: u32,
    ) -> Option<usize> {
        let mut off = base;
        for i in 0..count {
            if read_u32_le(mem, off) == fw_id {
                return Some(i);
            }
            off += stride;
        }
        None
    }

    fn copy_record_to_slice(
        mem: &[u8],
        off: usize,
        slice: &WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        slice
            .get(0..DPE_HANDLE_RECORD_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_from_slice(&mem[off..off + DPE_HANDLE_RECORD_SIZE]);
        Ok(())
    }

    fn do_read_record(&self, fw_id: u32, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        let records_base = self.records_base();
        let mem = self.mem.borrow();
        let count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        let index = Self::find_fw_id(&mem, records_base, DPE_HANDLE_RECORD_SIZE, count, fw_id)
            .ok_or(ErrorCode::FAIL)?;
        Self::copy_record_to_slice(&mem, Self::record_offset_from(records_base, index), slice)
    }

    fn do_write_record(&self, fw_id: u32, slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        let in_slice = slice
            .get(0..DPE_HANDLE_RECORD_SIZE)
            .ok_or(ErrorCode::SIZE)?;
        let records_base = self.records_base();
        let mut mem = self.mem.borrow_mut();
        let count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        let index = match Self::find_fw_id(&mem, records_base, DPE_HANDLE_RECORD_SIZE, count, fw_id)
        {
            Some(idx) => idx,
            None => {
                if count >= self.record_capacity_in(mem.len()) {
                    return Err(ErrorCode::NOMEM);
                }
                write_u32_le(&mut mem, META_RECORD_COUNT, count as u32 + 1);
                count
            }
        };
        let off = Self::record_offset_from(records_base, index);
        in_slice.copy_to_slice(&mut mem[off..off + DPE_HANDLE_RECORD_SIZE]);
        write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
        Ok(())
    }

    fn do_initialize_store(&self, digest_slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        let in_digest = digest_slice
            .get(0..POLICY_DIGEST_SIZE)
            .ok_or(ErrorCode::SIZE)?;
        let records_base = self.records_base();
        let mut mem = self.mem.borrow_mut();
        if mem.len() < records_base {
            return Err(ErrorCode::NOMEM);
        }
        let capacity = self.record_capacity_in(mem.len());
        write_u32_le(&mut mem, META_MAGIC, HEADER_MAGIC);
        mem[META_VERSION] = HEADER_VERSION;
        mem[5] = 0;
        write_u16_le(&mut mem, META_HEADER_SIZE, META_SIZE as u16);
        write_u16_le(&mut mem, META_RECORD_SIZE, DPE_HANDLE_RECORD_SIZE as u16);
        write_u16_le(&mut mem, META_RECORD_CAPACITY, capacity as u16);
        write_u32_le(&mut mem, META_RECORD_COUNT, 0);
        write_u32_le(&mut mem, META_ATTEST_TARGET, SENTINEL_NONE);
        write_u16_le(
            &mut mem,
            META_EXPORTED_CDI_CAPACITY,
            self.exported_cdi_capacity as u16,
        );
        write_u16_le(&mut mem, META_EXPORTED_CDI_COUNT, 0);
        in_digest
            .copy_to_slice(&mut mem[META_POLICY_DIGEST..META_POLICY_DIGEST + POLICY_DIGEST_SIZE]);
        let slots_end = (records_base + capacity * DPE_HANDLE_RECORD_SIZE).min(mem.len());
        mem[META_SIZE..slots_end].fill(0);
        Ok(())
    }

    fn do_validate_store(&self, digest_slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        let in_digest = digest_slice
            .get(0..POLICY_DIGEST_SIZE)
            .ok_or(ErrorCode::SIZE)?;
        let records_base = self.records_base();
        let mem = self.mem.borrow();
        if mem.len() < records_base
            || read_u32_le(&mem, META_MAGIC) != HEADER_MAGIC
            || mem[META_VERSION] != HEADER_VERSION
            || read_u16_le(&mem, META_HEADER_SIZE) != META_SIZE as u16
            || read_u16_le(&mem, META_RECORD_SIZE) != DPE_HANDLE_RECORD_SIZE as u16
        {
            return Err(ErrorCode::FAIL);
        }
        let stored_cdi_capacity = read_u16_le(&mem, META_EXPORTED_CDI_CAPACITY) as usize;
        let cdi_count = read_u16_le(&mem, META_EXPORTED_CDI_COUNT) as usize;
        let stored_capacity = read_u16_le(&mem, META_RECORD_CAPACITY) as usize;
        let record_count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        if stored_cdi_capacity != self.exported_cdi_capacity
            || cdi_count > stored_cdi_capacity
            || stored_capacity != self.record_capacity_in(mem.len())
            || record_count > stored_capacity
        {
            return Err(ErrorCode::FAIL);
        }
        let mut provided = [0u8; POLICY_DIGEST_SIZE];
        in_digest.copy_to_slice(&mut provided);
        if mem[META_POLICY_DIGEST..META_POLICY_DIGEST + POLICY_DIGEST_SIZE] != provided[..] {
            return Err(ErrorCode::FAIL);
        }
        let attest_target = read_u32_le(&mem, META_ATTEST_TARGET);
        if attest_target != SENTINEL_NONE
            && Self::find_fw_id(
                &mem,
                records_base,
                DPE_HANDLE_RECORD_SIZE,
                record_count,
                attest_target,
            )
            .is_none()
        {
            return Err(ErrorCode::FAIL);
        }
        let mut slot_off = META_SIZE;
        for slot_idx in 0..cdi_count {
            let slot_fw_id = read_u32_le(&mem, slot_off + SLOT_FW_ID);
            let handle = &mem[slot_off + SLOT_HANDLE..slot_off + SLOT_HANDLE + EXPORTED_CDI_SIZE];
            if !handle.iter().any(|&b| b != 0)
                || Self::find_fw_id(
                    &mem,
                    records_base,
                    DPE_HANDLE_RECORD_SIZE,
                    record_count,
                    slot_fw_id,
                )
                .is_none()
                || Self::find_fw_id(
                    &mem,
                    META_SIZE,
                    EXPORTED_CDI_SLOT_SIZE,
                    slot_idx,
                    slot_fw_id,
                )
                .is_some()
            {
                return Err(ErrorCode::FAIL);
            }
            slot_off += EXPORTED_CDI_SLOT_SIZE;
        }
        Ok(())
    }

    fn do_read_leaf_record(&self, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        let records_base = self.records_base();
        let mem = self.mem.borrow();
        let count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        if count == 0 {
            return Err(ErrorCode::FAIL);
        }
        Self::copy_record_to_slice(
            &mem,
            Self::record_offset_from(records_base, count - 1),
            slice,
        )
    }

    fn do_mark_attestation_target(&self, fw_id: u32) -> Result<(), ErrorCode> {
        let records_base = self.records_base();
        let mut mem = self.mem.borrow_mut();
        let count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        if Self::find_fw_id(&mem, records_base, DPE_HANDLE_RECORD_SIZE, count, fw_id).is_none() {
            return Err(ErrorCode::FAIL);
        }
        write_u32_le(&mut mem, META_ATTEST_TARGET, fw_id);
        Ok(())
    }

    fn do_read_attestation_target(&self, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        let records_base = self.records_base();
        let mem = self.mem.borrow();
        let attest_fw_id = read_u32_le(&mem, META_ATTEST_TARGET);
        if attest_fw_id == SENTINEL_NONE {
            return Err(ErrorCode::FAIL);
        }
        let count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        let index = Self::find_fw_id(
            &mem,
            records_base,
            DPE_HANDLE_RECORD_SIZE,
            count,
            attest_fw_id,
        )
        .ok_or(ErrorCode::FAIL)?;
        Self::copy_record_to_slice(&mem, Self::record_offset_from(records_base, index), slice)
    }

    fn do_read_exported_cdi(
        &self,
        fw_id: u32,
        slice: &WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        let out_slice = slice.get(0..EXPORTED_CDI_SIZE).ok_or(ErrorCode::SIZE)?;
        let mem = self.mem.borrow();
        let count = read_u16_le(&mem, META_EXPORTED_CDI_COUNT) as usize;
        let slot_idx = if fw_id == SENTINEL_NONE {
            if count > 0 {
                0
            } else {
                return Err(ErrorCode::FAIL);
            }
        } else {
            Self::find_fw_id(&mem, META_SIZE, EXPORTED_CDI_SLOT_SIZE, count, fw_id)
                .ok_or(ErrorCode::FAIL)?
        };
        let off = Self::exported_cdi_slot_offset(slot_idx) + SLOT_HANDLE;
        out_slice.copy_from_slice(&mem[off..off + EXPORTED_CDI_SIZE]);
        Ok(())
    }

    fn do_write_exported_cdi(
        &self,
        fw_id: u32,
        slice: &ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        let in_slice = slice.get(0..EXPORTED_CDI_SIZE).ok_or(ErrorCode::SIZE)?;
        let mut handle = [0u8; EXPORTED_CDI_SIZE];
        in_slice.copy_to_slice(&mut handle);
        if !handle.iter().any(|&b| b != 0) {
            return Err(ErrorCode::INVAL);
        }
        let records_base = self.records_base();
        let mut mem = self.mem.borrow_mut();
        let rec_count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        if Self::find_fw_id(&mem, records_base, DPE_HANDLE_RECORD_SIZE, rec_count, fw_id).is_none()
        {
            return Err(ErrorCode::FAIL);
        }
        let count = read_u16_le(&mem, META_EXPORTED_CDI_COUNT) as usize;
        let slot_idx = match Self::find_fw_id(&mem, META_SIZE, EXPORTED_CDI_SLOT_SIZE, count, fw_id)
        {
            Some(idx) => idx,
            None => {
                if count >= self.exported_cdi_capacity {
                    return Err(ErrorCode::NOMEM);
                }
                write_u16_le(&mut mem, META_EXPORTED_CDI_COUNT, count as u16 + 1);
                let off = Self::exported_cdi_slot_offset(count);
                write_u32_le(&mut mem, off + SLOT_FW_ID, fw_id);
                count
            }
        };
        let off = Self::exported_cdi_slot_offset(slot_idx) + SLOT_HANDLE;
        mem[off..off + EXPORTED_CDI_SIZE].copy_from_slice(&handle);
        Ok(())
    }

    fn do_clear_exported_cdi(&self, fw_id: u32) -> Result<(), ErrorCode> {
        let mut mem = self.mem.borrow_mut();
        let count = read_u16_le(&mem, META_EXPORTED_CDI_COUNT) as usize;
        let slot_idx = Self::find_fw_id(&mem, META_SIZE, EXPORTED_CDI_SLOT_SIZE, count, fw_id)
            .ok_or(ErrorCode::FAIL)?;
        for i in slot_idx..(count - 1) {
            let dst_off = Self::exported_cdi_slot_offset(i);
            let src_off = dst_off + EXPORTED_CDI_SLOT_SIZE;
            mem.copy_within(src_off..src_off + EXPORTED_CDI_SLOT_SIZE, dst_off);
        }
        let last_off = Self::exported_cdi_slot_offset(count - 1);
        mem[last_off..last_off + EXPORTED_CDI_SLOT_SIZE].fill(0);
        write_u16_le(&mut mem, META_EXPORTED_CDI_COUNT, (count - 1) as u16);
        Ok(())
    }
}

impl SyscallDriver for DpeHandleStore {
    fn command(
        &self,
        cmd_num: usize,
        arg1: usize,
        _arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        let cmd = cmd_num as u32;
        let fw_id = arg1 as u32;
        match cmd {
            cmd::EXISTS => CommandReturn::success(),

            cmd::READ_RECORD
            | cmd::READ_LEAF_RECORD
            | cmd::READ_ATTESTATION_TARGET
            | cmd::READ_EXPORTED_CDI => {
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(rw_allow::OUTPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.mut_enter(|slice| match cmd {
                                cmd::READ_RECORD => self.do_read_record(fw_id, slice),
                                cmd::READ_LEAF_RECORD => self.do_read_leaf_record(slice),
                                cmd::READ_ATTESTATION_TARGET => {
                                    self.do_read_attestation_target(slice)
                                }
                                _ => self.do_read_exported_cdi(fw_id, slice),
                            })
                            .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::WRITE_RECORD
            | cmd::INITIALIZE_STORE
            | cmd::VALIDATE_STORE
            | cmd::WRITE_EXPORTED_CDI => {
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| match cmd {
                                cmd::WRITE_RECORD => self.do_write_record(fw_id, slice),
                                cmd::INITIALIZE_STORE => self.do_initialize_store(slice),
                                cmd::VALIDATE_STORE => self.do_validate_store(slice),
                                _ => self.do_write_exported_cdi(fw_id, slice),
                            })
                            .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::MARK_ATTESTATION_TARGET => match self.do_mark_attestation_target(fw_id) {
                Ok(()) => CommandReturn::success(),
                Err(e) => CommandReturn::failure(e),
            },

            cmd::CLEAR_EXPORTED_CDI => match self.do_clear_exported_cdi(fw_id) {
                Ok(()) => CommandReturn::success(),
                Err(e) => CommandReturn::failure(e),
            },

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

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

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const READ_RECORD: u32 = 1;
    pub const WRITE_RECORD: u32 = 2;
    pub const INITIALIZE_STORE: u32 = 3;
    pub const READ_LEAF_RECORD: u32 = 4;
    pub const MARK_ATTESTATION_TARGET: u32 = 5;
    pub const READ_ATTESTATION_TARGET: u32 = 6;
    pub const VALIDATE_STORE: u32 = 7;
    pub const READ_EXPORTED_CDI: u32 = 8;
    pub const WRITE_EXPORTED_CDI: u32 = 9;
    pub const CLEAR_EXPORTED_CDI: u32 = 10;
}

impl DpeHandleStore {
    pub fn get_driver_num(&self) -> usize {
        self.driver_num
    }
}
