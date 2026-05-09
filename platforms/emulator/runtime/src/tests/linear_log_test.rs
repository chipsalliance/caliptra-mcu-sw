// Licensed under the Apache-2.0 license

// Based on Tock log test framework with modifications.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_emulator::logging::logging_flash as log;
use capsules_emulator::logging::logging_flash::{ENTRY_HEADER_SIZE, PAGE_HEADER_SIZE};
use core::cell::Cell;
use core::ptr::addr_of_mut;
use kernel::debug;
use kernel::hil::flash;
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::static_init;
use kernel::storage_volume;
use kernel::utilities::cells::{NumericCellExt, TakeCell};
use kernel::ErrorCode;
use mcu_platforms_common::{read_volatile_at, read_volatile_slice};
use mcu_tock_veer::timers::InternalTimers;

// Allocate 1KB storage volume for the linear log test. It resides on flash.
storage_volume!(LINEAR_TEST_LOG, 1);

const PAGE_SIZE: usize = 256;
const USABLE_PER_PAGE: usize = PAGE_SIZE - PAGE_HEADER_SIZE;
const MAX_ENTRY_SIZE: usize = USABLE_PER_PAGE - ENTRY_HEADER_SIZE;
const SMALL_ENTRY_SIZE: usize = 32;
const MEDIUM_ENTRY_SIZE: usize = 64;
const LOG_FLASH_BASE_ADDR: u32 = mcu_config_emulator::flash::LOGGING_FLASH_CONFIG.base_addr;

pub unsafe fn run(
    mux_alarm: &'static MuxAlarm<'static, InternalTimers>,
    flash_controller: &'static flash_ctrl_emulator::EmulatedFlashCtrl,
) -> Option<u32> {
    flash_controller.init();
    let pagebuffer = static_init!(
        flash_ctrl_emulator::EmulatedFlashPage,
        flash_ctrl_emulator::EmulatedFlashPage::default()
    );
    // Create actual log storage abstraction on top of flash.
    let log: &'static mut Log = static_init!(
        Log,
        log::Log::new(&LINEAR_TEST_LOG, flash_controller, pagebuffer, false)
    );
    // Set up the flash base address for the log storage
    log.set_flash_base_address(LOG_FLASH_BASE_ADDR);
    kernel::deferred_call::DeferredCallClient::register(log);
    flash::HasClient::set_client(flash_controller, log);

    let alarm = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    alarm.setup();

    // Create and run test for log storage.
    let test = static_init!(
        LogTest<VirtualMuxAlarm<'static, InternalTimers>>,
        LogTest::new(log, &mut *addr_of_mut!(BUFFER), alarm, &TEST_OPS)
    );
    log.set_read_client(test);
    log.set_append_client(test);
    test.alarm.set_alarm_client(test);

    test.schedule_next();

    // Integration tests are executed before kernel loop.
    // Explicitly advance the kernel to handle deferred calls and interrupt processing.
    while !test.finished() {
        crate::board::run_kernel_op(1);
    }

    Some(0)
}

static TEST_OPS: [TestOp; 19] = [
    TestOp::Read,
    // Fill first page with small entries
    TestOp::Write(SMALL_ENTRY_SIZE),
    TestOp::Write(SMALL_ENTRY_SIZE),
    TestOp::Write(SMALL_ENTRY_SIZE),
    TestOp::Write(SMALL_ENTRY_SIZE),
    TestOp::Write(SMALL_ENTRY_SIZE),
    TestOp::Write(SMALL_ENTRY_SIZE),
    // Fill second page with medium entries
    TestOp::Write(MEDIUM_ENTRY_SIZE),
    TestOp::Write(MEDIUM_ENTRY_SIZE),
    TestOp::Write(MEDIUM_ENTRY_SIZE),
    // Fill third page with a large entry
    TestOp::Write(MAX_ENTRY_SIZE),
    // Fill fourth page with a mix
    TestOp::Write(SMALL_ENTRY_SIZE),
    TestOp::Write(MEDIUM_ENTRY_SIZE),
    // Negative test: should fail (no space left)
    TestOp::Write(MAX_ENTRY_SIZE),
    // Read back everything to verify
    TestOp::Read,
    TestOp::Sync,
    // Fill the fourth page: try a small entry again
    TestOp::Write(SMALL_ENTRY_SIZE),
    // Add a final read
    TestOp::Read,
    // Erase entire log
    TestOp::Erase,
];

// Buffer for reading from and writing to in the log tests.
static mut BUFFER: [u8; 256] = [0; 256];
// Time to wait in between log operations.
const WAIT_MS: u32 = 50;

// A single operation within the test.
#[derive(Clone, Copy, PartialEq)]
enum TestOp {
    Read,
    Write(usize),
    Sync,
    Erase,
}

type Log = log::Log<'static, flash_ctrl_emulator::EmulatedFlashCtrl<'static>>;
struct LogTest<A: 'static + Alarm<'static>> {
    log: &'static Log,
    buffer: TakeCell<'static, [u8]>,
    alarm: &'static A,
    ops: &'static [TestOp],
    op_index: Cell<usize>,
}

impl<A: 'static + Alarm<'static>> LogTest<A> {
    fn new(
        log: &'static Log,
        buffer: &'static mut [u8],
        alarm: &'static A,
        ops: &'static [TestOp],
    ) -> LogTest<A> {
        romtime::println!(
            "Log recovered from flash (Start and end entry IDs: {:?} to {:?})",
            log.log_start(),
            log.log_end()
        );

        LogTest {
            log,
            buffer: TakeCell::new(buffer),
            alarm,
            ops,
            op_index: Cell::new(0),
        }
    }

    fn finished(&self) -> bool {
        self.op_index.get() >= self.ops.len()
    }

    fn run(&self) {
        let op_index = self.op_index.get();
        if self.finished() {
            romtime::println!("Linear Log Storage test succeeded!");
            return;
        }
        match self.ops[op_index] {
            TestOp::Read => self.read(),
            TestOp::Write(len) => self.write(len),
            TestOp::Sync => self.sync(),
            TestOp::Erase => self.erase(),
        }
    }

    fn read(&self) {
        self.buffer.take().map_or_else(
            || panic!("NO BUFFER"),
            move |buffer| {
                // Clear buffer first to ensure no stale data.
                buffer.fill(0);
                if let Err((error, original_buffer)) = self.log.read(buffer, buffer.len()) {
                    self.buffer.replace(original_buffer);
                    match error {
                        ErrorCode::FAIL => {
                            // No more entries, start writing again.
                            self.op_index.increment();
                            self.schedule_next();
                        }
                        ErrorCode::BUSY => {
                            self.wait();
                        }
                        _ => panic!("READ FAILED: {:?}", error),
                    }
                }
            },
        );
    }

    fn write(&self, len: usize) {
        self.buffer
            .take()
            .map(move |buffer| {
                let expect_write_fail = self.log.log_end() + len > LINEAR_TEST_LOG.len();
                // Set buffer value.
                buffer.iter_mut().enumerate().for_each(|(i, byte)| {
                    *byte = if i < len { len as u8 } else { 0 };
                });

                if let Err((error, original_buffer)) = self.log.append(buffer, len) {
                    self.buffer.replace(original_buffer);

                    match error {
                        ErrorCode::FAIL =>
                            if expect_write_fail {
                                self.op_index.increment();
                                self.schedule_next();
                            } else {
                                panic!(
                                    "Write failed unexpectedly on {} byte write (read entry ID: {:?}, append entry ID: {:?})",
                                    len,
                                    self.log.next_read_entry_id(),
                                    self.log.log_end()
                                );
                            }
                        ErrorCode::BUSY => self.wait(),
                        _ => panic!("Log test write: WRITE FAILED: {:?}", error),
                    }
                } else if expect_write_fail {
                    panic!(
                        "Write succeeded unexpectedly on {} byte write (read entry ID: {:?}, append entry ID: {:?})",
                        len,
                        self.log.next_read_entry_id(),
                        self.log.log_end()
                    );
                }
            })
            .unwrap();
    }

    fn sync(&self) {
        match self.log.sync() {
            Ok(()) => (),
            error => panic!("Sync failed: {:?}", error),
        }
    }

    fn schedule_next(&self) {
        let delay = self.alarm.ticks_from_ms(1);
        let now = self.alarm.now();
        self.alarm.set_alarm(now, delay);
    }

    fn wait(&self) {
        let delay = self.alarm.ticks_from_ms(WAIT_MS);
        let now = self.alarm.now();
        self.alarm.set_alarm(now, delay);
    }

    fn erase(&self) {
        if let Err(e) = self.log.erase() {
            match e {
                ErrorCode::BUSY => self.wait(),
                _ => panic!("Erase failed: {:?}", e),
            }
        }
    }
}

impl<A: Alarm<'static>> LogReadClient for LogTest<A> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize, error: Result<(), ErrorCode>) {
        match error {
            Ok(()) => {
                // Verify correct value was read.
                assert!(length > 0);
                buffer
                    .iter()
                    .take(length)
                    .enumerate()
                    .for_each(|(i, &byte)| {
                        assert_eq!(
                            byte, length as u8,
                            "Read incorrect value {} at index {}, expected {}",
                            byte, i, length
                        );
                    });
                self.buffer.replace(buffer);
                self.wait();
            }
            _ => {
                panic!("Read failed unexpectedly!");
            }
        }
    }

    fn seek_done(&self, _error: Result<(), ErrorCode>) {
        unreachable!();
    }
}

impl<A: Alarm<'static>> LogWriteClient for LogTest<A> {
    fn append_done(
        &self,
        buffer: &'static mut [u8],
        _length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        assert!(!records_lost);
        match error {
            Ok(()) => {
                self.buffer.replace(buffer);
                self.op_index.increment();
                self.wait();
            }
            error => panic!("WRITE FAILED IN CALLBACK: {:?}", error),
        }
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        if error != Ok(()) {
            panic!("Sync failed: {:?}", error);
        }

        self.op_index.increment();
        self.schedule_next();
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        match error {
            Ok(()) => {
                // print out the linear test log for debugging
                for i in 0..LINEAR_TEST_LOG.len() {
                    let byte = read_volatile_at!(&LINEAR_TEST_LOG, i);
                    assert_eq!(
                        byte, 0xFF,
                        "Log not fully erased at index {} byte {}",
                        i, byte
                    );
                }

                // Make sure that a read on an empty log fails normally.
                self.buffer.take().map(move |buffer| {
                    if let Err((error, original_buffer)) = self.log.read(buffer, buffer.len()) {
                        self.buffer.replace(original_buffer);
                        match error {
                            ErrorCode::FAIL => (),
                            ErrorCode::BUSY => {
                                self.wait();
                            }
                            _ => panic!("Read on empty log did not fail as expected: {:?}", error),
                        }
                    } else {
                        panic!("Read on empty log succeeded! (it shouldn't)");
                    }
                });

                self.op_index.increment();
                self.schedule_next();
            }
            Err(ErrorCode::BUSY) => {
                self.wait();
            }
            Err(e) => panic!("Erase failed: {:?}", e),
        }
    }
}

impl<A: Alarm<'static>> AlarmClient for LogTest<A> {
    fn alarm(&self) {
        self.run();
    }
}
