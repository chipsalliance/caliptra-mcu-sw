// Licensed under the Apache-2.0 license

//! Software PCR (Platform Configuration Register) storage capsule.
//!
//! Manages up to `PCR_COUNT` (32) SHA-384 measurements in a reserved SRAM
//! subregion.  All operations are **synchronous**; no upcalls are used.
//!
//! ## Driver number
//!
//! `0x8000_0021`
//!
//! ## SRAM layout
//!
//! ```text
//! offset 0 : pcr_valid_mask  u32 LE  (bit i = PCR index i contains a value)
//! offset 4 : pcr[0]          [u8; 48]  (SHA-384 measurement for index 0)
//! offset 52: pcr[1]          [u8; 48]
//! ...
//! offset 4 + i*48 : pcr[i]   [u8; 48]
//! ```
//!
//! ## Syscalls (all synchronous)
//!
//! | Command | Name                 | Arg0        | Allow           |
//! |---------|----------------------|-------------|-----------------|
//! | 0       | EXISTS               | —           | —               |
//! | 1       | READ_MEASUREMENT     | pcr_index   | RW 0 (output)   |
//! | 2       | WRITE_MEASUREMENT    | pcr_index   | RO 0 (input)    |
//! | 3       | CLEAR_MEASUREMENTS   | —           | —               |

use core::cell::RefCell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// Driver number for the Software PCR Store.
pub const DRIVER_NUM: usize = 0x8000_0021;

/// Size of one PCR measurement (SHA-384 = 48 bytes).
pub const PCR_MEASUREMENT_SIZE: usize = 48;

/// Maximum number of PCR indices supported.
pub const PCR_COUNT: usize = 32;

/// Total bytes required in the SRAM subregion:
/// 4-byte valid mask + 32 × 48-byte slots = 1540 bytes.
/// We reserve 0xC00 (3072) bytes so there is headroom.
pub const PCR_STORE_SIZE: usize = 0xC00;

const META_VALID_MASK: usize = 0; // u32 LE at [0..4]
const META_SIZE: usize = 4;

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
    pub const WRITE_MEASUREMENT: usize = 2;
    pub const CLEAR_MEASUREMENTS: usize = 3;
}

#[derive(Default)]
pub struct App {}

pub struct PcrStore {
    driver_num: usize,
    mem: RefCell<&'static mut [u8]>,
    apps: Grant<
        App,
        UpcallCount<0>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
}

impl PcrStore {
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

    fn slot_offset(pcr_index: usize) -> usize {
        META_SIZE + pcr_index * PCR_MEASUREMENT_SIZE
    }

    fn valid_mask(&self) -> u32 {
        let mem = self.mem.borrow();
        read_u32_le(&mem, META_VALID_MASK)
    }

    fn set_valid_mask(&self, mask: u32) {
        let mut mem = self.mem.borrow_mut();
        write_u32_le(&mut mem, META_VALID_MASK, mask);
    }

    fn is_valid(&self, pcr_index: usize) -> bool {
        pcr_index < PCR_COUNT && (self.valid_mask() & (1u32 << pcr_index)) != 0
    }

    fn do_read_measurement(
        &self,
        pcr_index: usize,
        slice: &kernel::processbuffer::WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if pcr_index >= PCR_COUNT {
            return Err(ErrorCode::INVAL);
        }
        if !self.is_valid(pcr_index) {
            return Err(ErrorCode::FAIL);
        }
        if slice.len() < PCR_MEASUREMENT_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let mem = self.mem.borrow();
        let off = Self::slot_offset(pcr_index);
        slice
            .get(0..PCR_MEASUREMENT_SIZE)
            .ok_or(ErrorCode::SIZE)?
            .copy_from_slice(&mem[off..off + PCR_MEASUREMENT_SIZE]);
        Ok(())
    }

    fn do_write_measurement(
        &self,
        pcr_index: usize,
        slice: &kernel::processbuffer::ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if pcr_index >= PCR_COUNT {
            return Err(ErrorCode::INVAL);
        }
        if slice.len() < PCR_MEASUREMENT_SIZE {
            return Err(ErrorCode::SIZE);
        }
        let off = Self::slot_offset(pcr_index);
        {
            let mut mem = self.mem.borrow_mut();
            slice
                .get(0..PCR_MEASUREMENT_SIZE)
                .ok_or(ErrorCode::SIZE)?
                .copy_to_slice(&mut mem[off..off + PCR_MEASUREMENT_SIZE]);
        }
        let new_mask = self.valid_mask() | (1u32 << pcr_index);
        self.set_valid_mask(new_mask);
        Ok(())
    }

    fn do_clear_measurements(&self) {
        let mut mem = self.mem.borrow_mut();
        // Clear the valid mask.
        for b in mem[..META_SIZE].iter_mut() {
            *b = 0;
        }
        // Zero all PCR slots.
        let slots_end = META_SIZE + PCR_COUNT * PCR_MEASUREMENT_SIZE;
        let slots_end = slots_end.min(mem.len());
        for b in mem[META_SIZE..slots_end].iter_mut() {
            *b = 0;
        }
    }
}

impl SyscallDriver for PcrStore {
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
                let pcr_index = arg0;
                let res = self.apps.enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(rw_allow::OUTPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.mut_enter(|slice| self.do_read_measurement(pcr_index, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                });
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::WRITE_MEASUREMENT => {
                let pcr_index = arg0;
                let res = self.apps.enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::INPUT)
                        .map_err(|_| ErrorCode::INVAL)
                        .and_then(|buf| {
                            buf.enter(|slice| self.do_write_measurement(pcr_index, slice))
                                .map_err(|_| ErrorCode::FAIL)?
                        })
                });
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::CLEAR_MEASUREMENTS => {
                self.apps
                    .enter(processid, |_, _| {
                        self.do_clear_measurements();
                    })
                    .unwrap_or(());
                CommandReturn::success()
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

impl PcrStore {
    pub fn get_driver_num(&self) -> usize {
        self.driver_num
    }
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
