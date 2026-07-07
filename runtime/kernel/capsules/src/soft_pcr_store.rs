// Licensed under the Apache-2.0 license

//! Software PCR Store capsule: stores `fw_id`-keyed current and journey
//! PCR-style measurement records for SoC non-TCB components in a reserved SRAM
//! subregion.
//!
//! The capsule takes exclusive ownership of a `&'static mut [u8]` slice that
//! covers the Software PCR Storage subregion of the measurement-store SRAM
//! reservation.  Capacity is derived from the slice length at construction
//! time; no count is hard-coded in the capsule.  All operations are
//! **synchronous**; no upcalls are used.
//!
//! ## Driver number
//!
//! `0x8000_0021`
//!
//! ## SRAM layout
//!
//! ```text
//! offset  0 : header       SoftwarePcrStoreHeader (16 bytes)
//! offset 16 : records[0]   MeasurementRecord      (112 bytes)
//! offset 128: records[1]   MeasurementRecord      (112 bytes)
//! ...
//! ```
//!
//! ## Header (16 bytes, little-endian fields)
//!
//! ```text
//! magic:           u32   0x5350_4352 ("SPCR")
//! version:         u16   1
//! header_size:     u16   16
//! record_size:     u16   112
//! record_capacity: u16   derived from slice length
//! record_count:    u16   current number of valid records
//! _pad:            [u8; 2]
//! ```
//!
//! ## MeasurementRecord (112 bytes, little-endian fields)
//!
//! ```text
//! fw_id:          u32     (offset   0)
//! current_digest: [u8;48] (offset   4)
//! journey_digest: [u8;48] (offset  52)
//! svn:            u32     (offset 100)
//! version:        u32     (offset 104)
//! reserved:       [u8; 4] (offset 108)
//! ```
//!
//! ## Commands
//!
//! | # | Name               | Arg0  | Allow         |
//! |---|--------------------|-------|---------------|
//! | 0 | EXISTS             | —     | —             |
//! | 1 | READ_MEASUREMENT   | fw_id | RW 0 (output) |
//! | 2 | CREATE_MEASUREMENT | fw_id | RO 0 (input)  |
//! | 3 | UPDATE_MEASUREMENT | fw_id | RO 0 (input)  |
//! | 4 | INITIALIZE_STORE   | —     | —             |
//! | 5 | VALIDATE_STORE     | —     | —             |

use core::cell::RefCell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// Driver number for the Software PCR Store.
pub const DRIVER_NUM: usize = 0x8000_0021;

/// Magic value written to the header on `INITIALIZE_STORE`.
const HEADER_MAGIC: u32 = 0x5350_4352; // "SPCR"
/// Supported header version.
const HEADER_VERSION: u16 = 1;

/// Serialized size of the `SoftwarePcrStoreHeader`.
pub const HEADER_SIZE: usize = 16;
/// Serialized size of one `MeasurementRecord`.
pub const MEASUREMENT_RECORD_SIZE: usize = 112;

// Header field byte offsets.
const META_MAGIC: usize = 0;
const META_VERSION: usize = 4;
const META_HEADER_SIZE: usize = 6;
const META_RECORD_SIZE: usize = 8;
const META_RECORD_CAPACITY: usize = 10;
const META_RECORD_COUNT: usize = 12;
// [14..16] _pad

// MeasurementRecord field byte offsets within a MEASUREMENT_RECORD_SIZE-byte slot.
const REC_FW_ID: usize = 0;
const _REC_CURRENT_DIGEST: usize = 4;
const _REC_JOURNEY_DIGEST: usize = 52;
const _REC_SVN: usize = 100;
const _REC_VERSION_FIELD: usize = 104;
// [108..112] reserved

mod ro_allow {
    pub const INPUT: usize = 0;
    pub const COUNT: u8 = 1;
}

mod rw_allow {
    pub const OUTPUT: usize = 0;
    pub const COUNT: u8 = 1;
}

mod cmd {
    pub const EXISTS: usize = 0;
    pub const READ_MEASUREMENT: usize = 1;
    pub const CREATE_MEASUREMENT: usize = 2;
    pub const UPDATE_MEASUREMENT: usize = 3;
    pub const INITIALIZE_STORE: usize = 4;
    pub const VALIDATE_STORE: usize = 5;
}

#[derive(Default)]
pub struct App {}

pub struct SoftPcrStore {
    driver_num: usize,
    mem: RefCell<&'static mut [u8]>,
    apps: Grant<
        App,
        UpcallCount<0>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
}

impl SoftPcrStore {
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

    /// Capacity derived from the assigned SRAM slice length.
    fn derived_capacity(sram_len: usize) -> u16 {
        let available = sram_len.saturating_sub(HEADER_SIZE);
        (available / MEASUREMENT_RECORD_SIZE).min(u16::MAX as usize) as u16
    }

    fn record_count(&self) -> u16 {
        let mem = self.mem.borrow();
        read_u16_le(&mem, META_RECORD_COUNT)
    }

    fn set_record_count(&self, count: u16) {
        let mut mem = self.mem.borrow_mut();
        write_u16_le(&mut mem, META_RECORD_COUNT, count);
    }

    fn slot_offset(index: usize) -> usize {
        HEADER_SIZE + index * MEASUREMENT_RECORD_SIZE
    }

    /// Search `records[0..record_count]` for `fw_id`; return its index if found.
    fn find_record_index(&self, fw_id: u32) -> Option<usize> {
        let mem = self.mem.borrow();
        let count = read_u16_le(&mem, META_RECORD_COUNT) as usize;
        for i in 0..count {
            let off = Self::slot_offset(i);
            if read_u32_le(&mem, off + REC_FW_ID) == fw_id {
                return Some(i);
            }
        }
        None
    }

    fn do_initialize_store(&self) {
        let cap = {
            let mem = self.mem.borrow();
            Self::derived_capacity(mem.len())
        };
        let slots_end = HEADER_SIZE + cap as usize * MEASUREMENT_RECORD_SIZE;
        let mut mem = self.mem.borrow_mut();
        let zero_end = slots_end.min(mem.len());
        for b in mem[..zero_end].iter_mut() {
            *b = 0;
        }
        write_u32_le(&mut mem, META_MAGIC, HEADER_MAGIC);
        write_u16_le(&mut mem, META_VERSION, HEADER_VERSION);
        write_u16_le(&mut mem, META_HEADER_SIZE, HEADER_SIZE as u16);
        write_u16_le(&mut mem, META_RECORD_SIZE, MEASUREMENT_RECORD_SIZE as u16);
        write_u16_le(&mut mem, META_RECORD_CAPACITY, cap);
        write_u16_le(&mut mem, META_RECORD_COUNT, 0);
    }

    fn do_validate_store(&self) -> Result<(), ErrorCode> {
        let mem = self.mem.borrow();
        let cap = Self::derived_capacity(mem.len());
        if read_u32_le(&mem, META_MAGIC) != HEADER_MAGIC {
            return Err(ErrorCode::FAIL);
        }
        if read_u16_le(&mem, META_VERSION) != HEADER_VERSION {
            return Err(ErrorCode::FAIL);
        }
        if read_u16_le(&mem, META_HEADER_SIZE) != HEADER_SIZE as u16 {
            return Err(ErrorCode::FAIL);
        }
        if read_u16_le(&mem, META_RECORD_SIZE) != MEASUREMENT_RECORD_SIZE as u16 {
            return Err(ErrorCode::FAIL);
        }
        if read_u16_le(&mem, META_RECORD_CAPACITY) != cap {
            return Err(ErrorCode::FAIL);
        }
        let count = read_u16_le(&mem, META_RECORD_COUNT);
        if count > cap {
            return Err(ErrorCode::FAIL);
        }
        Ok(())
    }

    fn do_read_measurement(
        &self,
        fw_id: u32,
        slice: &kernel::processbuffer::WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if slice.len() < MEASUREMENT_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let idx = self.find_record_index(fw_id).ok_or(ErrorCode::FAIL)?;
        let off = Self::slot_offset(idx);
        let mem = self.mem.borrow();
        slice
            .get(0..MEASUREMENT_RECORD_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_from_slice(&mem[off..off + MEASUREMENT_RECORD_SIZE]);
        Ok(())
    }

    fn do_create_measurement(
        &self,
        fw_id: u32,
        slice: &kernel::processbuffer::ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if slice.len() < MEASUREMENT_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        if self.find_record_index(fw_id).is_some() {
            return Err(ErrorCode::ALREADY);
        }
        let cap = {
            let mem = self.mem.borrow();
            Self::derived_capacity(mem.len())
        };
        let count = self.record_count();
        if count as usize >= cap as usize {
            return Err(ErrorCode::NOMEM);
        }
        let off = Self::slot_offset(count as usize);
        {
            let mut mem = self.mem.borrow_mut();
            slice
                .get(0..MEASUREMENT_RECORD_SIZE)
                .ok_or(ErrorCode::SIZE)?
                .copy_to_slice(&mut mem[off..off + MEASUREMENT_RECORD_SIZE]);
            // Ensure fw_id in the slot is consistent with the command argument.
            write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
        }
        self.set_record_count(count + 1);
        Ok(())
    }

    fn do_update_measurement(
        &self,
        fw_id: u32,
        slice: &kernel::processbuffer::ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if slice.len() < MEASUREMENT_RECORD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let idx = self.find_record_index(fw_id).ok_or(ErrorCode::FAIL)?;
        let off = Self::slot_offset(idx);
        let mut mem = self.mem.borrow_mut();
        slice
            .get(0..MEASUREMENT_RECORD_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_to_slice(&mut mem[off..off + MEASUREMENT_RECORD_SIZE]);
        // Preserve fw_id in the slot.
        write_u32_le(&mut mem, off + REC_FW_ID, fw_id);
        Ok(())
    }
}

impl SyscallDriver for SoftPcrStore {
    fn command(
        &self,
        command_num: usize,
        arg0: usize,
        _arg1: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            cmd::EXISTS => CommandReturn::success(),

            cmd::READ_MEASUREMENT => {
                let fw_id = arg0 as u32;
                let res = self.apps.enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(rw_allow::OUTPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.mut_enter(|slice| self.do_read_measurement(fw_id, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                });
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::CREATE_MEASUREMENT => {
                let fw_id = arg0 as u32;
                let res = self.apps.enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| self.do_create_measurement(fw_id, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                });
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::UPDATE_MEASUREMENT => {
                let fw_id = arg0 as u32;
                let res = self.apps.enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| self.do_update_measurement(fw_id, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                });
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::INITIALIZE_STORE => {
                self.apps
                    .enter(processid, |_, _| {
                        self.do_initialize_store();
                    })
                    .unwrap_or(());
                CommandReturn::success()
            }

            cmd::VALIDATE_STORE => {
                let res = self.apps.enter(processid, |_, _| self.do_validate_store());
                match res {
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

impl SoftPcrStore {
    pub fn get_driver_num(&self) -> usize {
        self.driver_num
    }
}

#[inline]
fn read_u16_le(mem: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([mem[offset], mem[offset + 1]])
}

#[inline]
fn write_u16_le(mem: &mut [u8], offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    mem[offset] = bytes[0];
    mem[offset + 1] = bytes[1];
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
    let bytes = val.to_le_bytes();
    mem[offset] = bytes[0];
    mem[offset + 1] = bytes[1];
    mem[offset + 2] = bytes[2];
    mem[offset + 3] = bytes[3];
}
