// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Tests the log storage interface in linear mode. For testing in circular mode, see
//! log_test.rs.
//!
//! The testing framework creates a non-circular log storage interface in flash and performs a
//! series of writes and syncs to ensure that the non-circular log properly denies overly-large
//! writes once it is full. For testing all of the general capabilities of the log storage
//! interface, see log_test.rs.
//!
//! To run the test, add the following line to the imix boot sequence:
//! ```
//!     test::linear_log_test::run(mux_alarm);
//! ```
//! and use the `USER` and `RESET` buttons to manually erase the log and reboot the imix,
//! respectively.

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_emulator::logging as log;
use core::cell::Cell;
use core::ptr::addr_of_mut;
use flash_driver::flash_ctrl;
use kernel::debug;
use kernel::hil::flash;
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::static_init;
use kernel::storage_volume;
use kernel::utilities::cells::{NumericCellExt, TakeCell};
use kernel::ErrorCode;
use capsules_emulator::logging::{ENTRY_HEADER_SIZE, PAGE_HEADER_SIZE};
use mcu_tock_veer::timers::InternalTimers;

use core::fmt::Write;
use romtime::println;

// Allocate a storage volume for the linear log test. This is 1KB in size.
storage_volume!(LINEAR_TEST_LOG, 1);

const PAGE_SIZE: usize = 256; // LINEAR_TEST_LOG is 1KB, 4 pages of 256 bytes each
const USABLE_PER_PAGE: usize = PAGE_SIZE - PAGE_HEADER_SIZE;
const MAX_ENTRY_SIZE: usize = USABLE_PER_PAGE - ENTRY_HEADER_SIZE;
const SMALL_ENTRY_SIZE: usize = 32;
const MEDIUM_ENTRY_SIZE: usize = 64;

#[cfg(feature = "test-linear-log-flash")]
use crate::board::run_kernel_op;

const LOG_FLASH_BASE_ADDR: u32 = 0x3800_0000;

pub unsafe fn run(
    mux_alarm: &'static MuxAlarm<'static, InternalTimers>,
    flash_controller: &'static flash_ctrl::EmulatedFlashCtrl,
) -> Option<u32> {
    // Initialize flash controller driver
    flash_controller.init();

    let pagebuffer = static_init!(
        flash_ctrl::EmulatedFlashPage,
        flash_ctrl::EmulatedFlashPage::default()
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
        LogTest::new(
            log,
            &mut *addr_of_mut!(BUFFER),
            alarm,
            &TEST_OPS,
            &LINEAR_TEST_LOG
        )
    );
    log.set_read_client(test);
    log.set_append_client(test);
    test.alarm.set_alarm_client(test);

    test.run();

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

type Log = log::Log<'static, flash_ctrl::EmulatedFlashCtrl<'static>>;
struct LogTest<A: 'static + Alarm<'static>> {
    log: &'static Log,
    buffer: TakeCell<'static, [u8]>,
    alarm: &'static A,
    ops: &'static [TestOp],
    op_index: Cell<usize>,
    test_log_volume: &'static [u8],
}

impl<A: 'static + Alarm<'static>> LogTest<A> {
    fn new(
        log: &'static Log,
        buffer: &'static mut [u8],
        alarm: &'static A,
        ops: &'static [TestOp],
        test_log_volume: &'static [u8],
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
            test_log_volume,
        }
    }

    fn run(&self) {
        let op_index = self.op_index.get();

        romtime::println!("[xs debug] LogTest: Running operation index {}", op_index);

        if op_index == self.ops.len() {
            romtime::println!("Linear Log Storage test succeeded!");
            return;
        }

        match self.ops[op_index] {
            TestOp::Read => self.read(),
            TestOp::Write(len) => self.write(len),
            TestOp::Sync => self.sync(),
            TestOp::Erase => self.erase(),
        }

        #[cfg(feature = "test-linear-log-flash")]
        run_kernel_op(1000); // Ensure kernel loop runs to process the alarm
    }

    fn read(&self) {
        self.buffer.take().map_or_else(
            || panic!("NO BUFFER"),
            move |buffer| {
                // Clear buffer first to make debugging more sane.
                for e in buffer.iter_mut() {
                    *e = 0;
                }

                if let Err((error, original_buffer)) = self.log.read(buffer, buffer.len()) {
                    self.buffer.replace(original_buffer);
                    match error {
                        ErrorCode::FAIL => {
                            // No more entries, start writing again.
                            romtime::println!(
                                "[xs debug]Expected: nothing to read! READ DONE: READ OFFSET: {:?} / WRITE OFFSET: {:?}",
                                self.log.next_read_entry_id(),
                                self.log.log_end()
                            );
                            self.op_index.increment();
                            self.run();
                        }
                        ErrorCode::BUSY => {
                            romtime::println!("Flash busy, waiting before reattempting read");
                            self.wait();
                        }
                        _ => panic!("[xs debug]READ FAILED: {:?}", error),
                    }
                }
            },
        );
    }

    fn write(&self, len: usize) {
        self.buffer
            .take()
            .map(move |buffer| {
                let expect_write_fail = self.log.log_end() + len > self.test_log_volume.len();

                romtime::println!("[xs debug]LogTest: Writing {} bytes to log: append entry ID: {:?}, expected_write_fail(true/false): {}",
                                len, self.log.log_end(), expect_write_fail);

                // Set buffer value.
                for i in 0..buffer.len() {
                    buffer[i] = if i < len {
                        len as u8
                    } else {
                        0
                    };
                }

                if let Err((error, original_buffer)) = self.log.append(buffer, len) {
                    self.buffer.replace(original_buffer);

                    match error {
                        ErrorCode::FAIL =>
                            if expect_write_fail {
                                romtime::println!(
                                    "[xs debug]Write failed on {} byte write, as expected",
                                    len
                                );
                                self.op_index.increment();
                                self.run();
                            } else {
                                panic!(
                                    "Write failed unexpectedly on {} byte write (read entry ID: {:?}, append entry ID: {:?})",
                                    len,
                                    self.log.next_read_entry_id(),
                                    self.log.log_end()
                                );
                            }
                        ErrorCode::BUSY => self.wait(),
                        _ => panic!("[xs debug]Log test write: WRITE FAILED: {:?}", error),
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

    fn wait(&self) {
        let delay = self.alarm.ticks_from_ms(WAIT_MS);
        let now = self.alarm.now();
        romtime::println!(
            "[xs debug] Setting alarm for now={:?} delay={:?}",
            now,
            delay
        );
        self.alarm.set_alarm(now, delay);
    }

    fn erase(&self) {
        match self.log.erase() {
            Ok(()) => (),
            Err(ErrorCode::BUSY) => {
                romtime::println!("[xs debug]Flash busy, waiting before reattempting erase");
                self.wait();
            }
            Err(e) => panic!("Erase failed: {:?}", e),
        }
    }
}

impl<A: Alarm<'static>> LogReadClient for LogTest<A> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize, error: Result<(), ErrorCode>) {
        match error {
            Ok(()) => {
                // Verify correct value was read.
                assert!(length > 0);
                for i in 0..length {
                    if buffer[i] != length as u8 {
                        panic!(
                            "Read incorrect value {} at index {}, expected {}",
                            buffer[i], i, length
                        );
                    }
                }
                romtime::println!("[xs debug]read_done: Successful read of size {}", length);
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
        length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        assert!(!records_lost);
        match error {
            Ok(()) => {
                romtime::println!(
                    "[xs debug]append_done: Write succeeded on {} byte write, as expected",
                    length
                );

                self.buffer.replace(buffer);
                self.op_index.increment();
                self.wait();
            }
            error => panic!("WRITE FAILED IN CALLBACK: {:?}", error),
        }
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        if error == Ok(()) {
            romtime::println!(
                "[xs debug]SYNC DONE: READ OFFSET: {:?} / WRITE OFFSET: {:?}",
                self.log.next_read_entry_id(),
                self.log.log_end()
            );
        } else {
            panic!("Sync failed: {:?}", error);
        }

        self.op_index.increment();
        self.run();
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        match error {
            Ok(()) => {
                romtime::println!("[xs debug]ERASE DONE");
                romtime::println!(
                    "(Start and end entry IDs: {:?} to {:?})",
                    self.log.log_start(),
                    self.log.log_end()
                );
                self.op_index.increment();
                self.run();
            }
            Err(ErrorCode::BUSY) => {
                romtime::println!("[xs debug]Erase busy, retrying...");
                self.wait();
            }
            Err(e) => panic!("Erase failed: {:?}", e),
        }
    }
}

impl<A: Alarm<'static>> AlarmClient for LogTest<A> {
    fn alarm(&self) {
        romtime::println!(
            "[xs debug]AlarmClient::alarm() invoked, starting test: op_index: {}",
            self.op_index.get()
        );
        self.run();
    }
}
