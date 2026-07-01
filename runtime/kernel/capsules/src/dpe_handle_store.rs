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
//! ### Header (72 bytes)
//!
//! ```text
//! offset  0 : magic                     u32 LE  (0xD9E4_C7A1)
//! offset  4 : version                   u8      (1)
//! offset  5 : _pad                      u8
//! offset  6 : header_size               u16 LE  (72)
//! offset  8 : record_size               u16 LE  (DPE_HANDLE_RECORD_SIZE = 32)
//! offset 10 : record_capacity           u16 LE
//! offset 12 : record_count              u32 LE
//! offset 16 : attestation_target_fw_id  u32 LE  (0xFFFF_FFFF = none)
//! offset 20 : _pad                      [u8; 4]
//! offset 24 : attestation_policy_digest [u8; 48]
//! offset 72 : records[0..capacity]      DPE_HANDLE_RECORD_SIZE bytes each
//! ```
//!
//! Records at indices 0..(record_count-1) are all valid.  The `flags` byte
//! within each record (offset 28) is **reserved** — the capsule does not
//! interpret it for validity.  Record validity is determined solely by
//! position relative to `record_count`.
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

use core::cell::RefCell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

pub const DPE_STORE_SIZE: usize = 0x400;
pub const DRIVER_NUM: usize = 0x8000_0020;
pub const DPE_HANDLE_RECORD_SIZE: usize = 32;
pub const POLICY_DIGEST_SIZE: usize = 48;

const HEADER_MAGIC: u32 = 0xD9E4_C7A1;
const HEADER_VERSION: u8 = 1;
const SENTINEL_NONE: u32 = 0xFFFF_FFFF;

const META_MAGIC: usize = 0;
const META_VERSION: usize = 4;
const META_HEADER_SIZE: usize = 6;
const META_RECORD_SIZE: usize = 8;
const META_RECORD_CAPACITY: usize = 10;
const META_RECORD_COUNT: usize = 12;
const META_ATTEST_TARGET: usize = 16;
const META_POLICY_DIGEST: usize = 24;
const META_SIZE: usize = 72;

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
        read_u32_le(&mem, META_RECORD_COUNT) as usize
    }

    fn set_record_count(&self, count: u32) {
        let mut mem = self.mem.borrow_mut();
        write_u32_le(&mut mem, META_RECORD_COUNT, count);
    }

    fn attestation_target_fw_id(&self) -> u32 {
        let mem = self.mem.borrow();
        read_u32_le(&mem, META_ATTEST_TARGET)
    }

    fn set_attestation_target_fw_id(&self, fw_id: u32) {
        let mut mem = self.mem.borrow_mut();
        write_u32_le(&mut mem, META_ATTEST_TARGET, fw_id);
    }

    fn record_offset(index: usize) -> usize {
        META_SIZE + index * DPE_HANDLE_RECORD_SIZE
    }

    /// Search records[0..record_count) for `fw_id`.
    /// All records below record_count are valid by definition.
    fn find_record_index(&self, fw_id: u32) -> Option<usize> {
        let count = self.record_count();
        let mem = self.mem.borrow();
        for i in 0..count {
            let off = Self::record_offset(i);
            if read_u32_le(&mem, off + REC_FW_ID) == fw_id {
                return Some(i);
            }
        }
        None
    }

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

    fn do_read_record(&self, fw_id: u32, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        let index = self.find_record_index(fw_id).ok_or(ErrorCode::FAIL)?;
        self.copy_record_to_slice(index, slice)
    }

    fn do_write_record(&self, fw_id: u32, slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        if slice.len() < DPE_HANDLE_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        if let Some(index) = self.find_record_index(fw_id) {
            let mut mem = self.mem.borrow_mut();
            let off = Self::record_offset(index);
            slice
                .get(0..DPE_HANDLE_RECORD_SIZE)
                .ok_or(ErrorCode::SIZE)?
                .copy_to_slice(&mut mem[off..off + DPE_HANDLE_RECORD_SIZE]);
            write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
            return Ok(());
        }
        let count = self.record_count();
        let capacity = self.record_capacity();
        if count >= capacity {
            return Err(ErrorCode::NOMEM);
        }
        {
            let mut mem = self.mem.borrow_mut();
            let off = Self::record_offset(count);
            slice
                .get(0..DPE_HANDLE_RECORD_SIZE)
                .ok_or(ErrorCode::SIZE)?
                .copy_to_slice(&mut mem[off..off + DPE_HANDLE_RECORD_SIZE]);
            write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
        }
        self.set_record_count(count as u32 + 1);
        Ok(())
    }

    fn do_initialize_store(&self, digest_slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        if digest_slice.len() < POLICY_DIGEST_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let capacity = self.record_capacity();
        let mut mem = self.mem.borrow_mut();
        write_u32_le(&mut mem, META_MAGIC, HEADER_MAGIC);
        mem[META_VERSION] = HEADER_VERSION;
        mem[5] = 0;
        write_u16_le(&mut mem, META_HEADER_SIZE, META_SIZE as u16);
        write_u16_le(&mut mem, META_RECORD_SIZE, DPE_HANDLE_RECORD_SIZE as u16);
        write_u16_le(&mut mem, META_RECORD_CAPACITY, capacity as u16);
        write_u32_le(&mut mem, META_RECORD_COUNT, 0);
        write_u32_le(&mut mem, META_ATTEST_TARGET, SENTINEL_NONE);
        for b in mem[20..24].iter_mut() {
            *b = 0;
        }
        digest_slice
            .get(0..POLICY_DIGEST_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_to_slice(&mut mem[META_POLICY_DIGEST..META_POLICY_DIGEST + POLICY_DIGEST_SIZE]);
        let slots_end = (META_SIZE + capacity * DPE_HANDLE_RECORD_SIZE).min(mem.len());
        for b in mem[META_SIZE..slots_end].iter_mut() {
            *b = 0;
        }
        Ok(())
    }

    fn do_validate_store(&self, digest_slice: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        if digest_slice.len() < POLICY_DIGEST_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let mem = self.mem.borrow();
        if read_u32_le(&mem, META_MAGIC) != HEADER_MAGIC {
            return Err(ErrorCode::FAIL);
        }
        if mem[META_VERSION] != HEADER_VERSION {
            return Err(ErrorCode::FAIL);
        }
        if read_u16_le(&mem, META_HEADER_SIZE) != META_SIZE as u16 {
            return Err(ErrorCode::FAIL);
        }
        if read_u16_le(&mem, META_RECORD_SIZE) != DPE_HANDLE_RECORD_SIZE as u16 {
            return Err(ErrorCode::FAIL);
        }
        let stored_capacity = read_u16_le(&mem, META_RECORD_CAPACITY) as usize;
        let computed_capacity = if mem.len() > META_SIZE {
            (mem.len() - META_SIZE) / DPE_HANDLE_RECORD_SIZE
        } else {
            0
        };
        if stored_capacity != computed_capacity {
            return Err(ErrorCode::FAIL);
        }
        let record_count = read_u32_le(&mem, META_RECORD_COUNT) as usize;
        if record_count > stored_capacity {
            return Err(ErrorCode::FAIL);
        }
        let stored = &mem[META_POLICY_DIGEST..META_POLICY_DIGEST + POLICY_DIGEST_SIZE];
        let mut provided = [0u8; POLICY_DIGEST_SIZE];
        digest_slice
            .get(0..POLICY_DIGEST_SIZE)
            .ok_or(ErrorCode::FAIL)?
            .copy_to_slice(&mut provided);
        if stored != &provided[..] {
            return Err(ErrorCode::FAIL);
        }
        let attest_target = read_u32_le(&mem, META_ATTEST_TARGET);
        if attest_target != SENTINEL_NONE {
            let found = (0..record_count).any(|i| {
                let off = META_SIZE + i * DPE_HANDLE_RECORD_SIZE;
                read_u32_le(&mem, off + REC_FW_ID) == attest_target
            });
            if !found {
                return Err(ErrorCode::FAIL);
            }
        }
        Ok(())
    }

    fn do_read_leaf_record(&self, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
        let count = self.record_count();
        if count == 0 {
            return Err(ErrorCode::FAIL);
        }
        self.copy_record_to_slice(count - 1, slice)
    }

    fn do_mark_attestation_target(&self, fw_id: u32) -> Result<(), ErrorCode> {
        if self.find_record_index(fw_id).is_none() {
            return Err(ErrorCode::FAIL);
        }
        self.set_attestation_target_fw_id(fw_id);
        Ok(())
    }

    fn do_read_attestation_target(&self, slice: &WriteableProcessSlice) -> Result<(), ErrorCode> {
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

            cmd::INITIALIZE_STORE => {
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| self.do_initialize_store(slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                }) {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
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

            cmd::VALIDATE_STORE => {
                match self.apps.enter(processid, |_app, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| self.do_validate_store(slice))
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
}

impl DpeHandleStore {
    pub fn get_driver_num(&self) -> usize {
        self.driver_num
    }
}
