// Licensed under the Apache-2.0 license

//! This provides the MCI capsule that calls the underlying MCI driver

use core::cell::RefCell;

use kernel::hil::time::{Alarm, AlarmClient};

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::ReadWriteable;
use kernel::{ErrorCode, ProcessId};
use registers_generated::mci;
use registers_generated::mci::bits::MboxExecute;
use romtime::StaticRef;
use tock_registers::interfaces::Readable;

pub const DRIVER_NUM_MCU_MBOX0_SRAM: usize = 0x9000_3000;
pub const DRIVER_NUM_MCU_MBOX1_SRAM: usize = 0x9000_3001;

#[derive(Default)]
pub struct App {}

pub struct MboxSram<'a, A: Alarm<'a>> {
    driver_num: usize,
    registers: StaticRef<mci::regs::Mci>,
    mem_ref: RefCell<&'static mut [u32]>,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    // Which app is currently using the storage.
    current_app: OptionalCell<ProcessId>,
    alarm: &'a A,
}

impl<'a, A: Alarm<'a>> MboxSram<'a, A> {
    const DEFER_SEND_DONE_TICKS: u32 = 1000;

    pub fn new(
        driver_num: usize,
        registers: StaticRef<mci::regs::Mci>,
        mem_ref: &'static mut [u32],
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        alarm: &'a A,
    ) -> MboxSram<'a, A> {
        MboxSram {
            driver_num,
            registers,
            mem_ref: RefCell::new(mem_ref),
            apps: grant,
            alarm,
            current_app: OptionalCell::empty(),
        }
    }

    pub fn init(&'static self) {
        self.alarm.set_alarm_client(self);
    }

    pub fn write(&self, offset: usize, processid: ProcessId) -> Result<(), ErrorCode> {
        if self.current_app.is_some() {
            return Err(ErrorCode::BUSY);
        }
        self.current_app.set(processid);
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readonly_processbuffer(ro_allow::WRITE_BUFFER)
                .map_err(|_| ErrorCode::FAIL)
                .and_then(|ro_buffer| {
                    ro_buffer
                        .enter(|app_buffer| self.memory_write(offset, app_buffer))
                        .map_err(|_| ErrorCode::FAIL)?
                })
        })?
    }

    pub fn read(&self, offset: usize, processid: ProcessId) -> Result<(), ErrorCode> {
        if self.current_app.is_some() {
            return Err(ErrorCode::BUSY);
        }
        self.current_app.set(processid);
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readwrite_processbuffer(rw_allow::READ_BUFFER)
                .map_err(|_| ErrorCode::FAIL)
                .and_then(|rw_buffer| {
                    rw_buffer
                        .mut_enter(|app_buffer| self.memory_read(offset, app_buffer))
                        .map_err(|_| ErrorCode::FAIL)?
                })
        })?
    }

    fn memory_write(
        &self,
        offset: usize,
        app_buffer: &ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        let mut mem_ref = self.mem_ref.borrow_mut();
        let len = core::cmp::min(mem_ref.len() - offset, app_buffer.len() / 4);
        for i in 0..len {
            let mut dword = [0u8; 4];
            app_buffer
                .get(i * 4..i * 4 + 4)
                .ok_or(ErrorCode::INVAL)?
                .copy_to_slice(&mut dword);
            mem_ref[offset + i] = u32::from_le_bytes(dword);
        }
        Ok(())
    }

    fn memory_read(
        &self,
        offset: usize,
        app_buffer: &WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        let mem_ref = self.mem_ref.borrow();
        let len = core::cmp::min(mem_ref.len() - offset, app_buffer.len() / 4);
        for i in 0..len {
            let dword = mem_ref[offset + i].to_le_bytes();
            app_buffer
                .get(i * 4..i * 4 + 4)
                .ok_or(ErrorCode::INVAL)?
                .copy_from_slice(&dword);
        }
        Ok(())
    }

    fn schedule_notify_done(&self) {
        let now = self.alarm.now();
        self.alarm
            .set_alarm(now, Self::DEFER_SEND_DONE_TICKS.into());
    }

    fn notify_done(&self, processid: ProcessId) {
        let _ = self.apps.enter(processid, |_, kernel_data| {
            kernel_data
                .schedule_upcall(upcall::DONE, (0, 0, 0))
                .map_err(|_| ErrorCode::FAIL)
        });
    }

    fn acquire_lock(&self) -> Result<(), ErrorCode> {
        match self.driver_num {
            DRIVER_NUM_MCU_MBOX0_SRAM => {
                if self.registers.mcu_mbox0_csr_mbox_lock.get() != 0 {
                    return Err(ErrorCode::BUSY);
                }
            }
            DRIVER_NUM_MCU_MBOX1_SRAM => {
                if self.registers.mcu_mbox1_csr_mbox_lock.get() != 0 {
                    return Err(ErrorCode::BUSY);
                }
            }
            _ => return Err(ErrorCode::INVAL),
        }
        Ok(())
    }

    fn release_lock(&self) -> Result<(), ErrorCode> {
        match self.driver_num {
            DRIVER_NUM_MCU_MBOX0_SRAM => {
                self.registers
                    .mcu_mbox0_csr_mbox_execute
                    .modify(MboxExecute::Execute::CLEAR);
            }
            DRIVER_NUM_MCU_MBOX1_SRAM => {
                self.registers
                    .mcu_mbox1_csr_mbox_execute
                    .modify(MboxExecute::Execute::CLEAR);
            }
            _ => return Err(ErrorCode::INVAL),
        }
        Ok(())
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for MboxSram<'a, A> {
    fn alarm(&self) {
        if let Some(process_id) = self.current_app.take() {
            self.notify_done(process_id);
        }
    }
}

/// Provide an interface for userland.
impl<'a, A: Alarm<'a>> SyscallDriver for MboxSram<'a, A> {
    fn command(&self, cmd: usize, arg1: usize, _: usize, processid: ProcessId) -> CommandReturn {
        if self.current_app.is_some() {
            return CommandReturn::failure(ErrorCode::BUSY);
        }
        let exec_result = match cmd as u32 {
            cmd::MEMORY_READ => {
                let res = self.read(arg1, processid);
                self.schedule_notify_done();
                res
            }
            cmd::MEMORY_WRITE => {
                let res = self.write(arg1, processid);
                self.schedule_notify_done();
                res
            }
            cmd::ACQUIRE_LOCK => self.acquire_lock(),
            cmd::RELEASE_LOCK => self.release_lock(),
            _ => Err(ErrorCode::NOSUPPORT),
        };
        match exec_result {
            Ok(()) => CommandReturn::success(),
            Err(e) => CommandReturn::failure(e),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

mod cmd {
    pub const MEMORY_READ: u32 = 1;
    pub const MEMORY_WRITE: u32 = 2;
    pub const ACQUIRE_LOCK: u32 = 3;
    pub const RELEASE_LOCK: u32 = 4;
}

/// IDs for subscribed upcalls.
mod upcall {
    pub const DONE: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for read-only allow buffers
mod ro_allow {
    pub const WRITE_BUFFER: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const READ_BUFFER: usize = 0;
    pub const COUNT: u8 = 1;
}
