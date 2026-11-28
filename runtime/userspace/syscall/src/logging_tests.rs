// Licensed under the Apache-2.0 license

extern crate std;
use super::*;
use caliptra_mcu_libtock_platform::CommandReturn;
use caliptra_mcu_libtock_unittest::{
    command_return, fake, DriverInfo, DriverShareRef, RoAllowBuffer, RwAllowBuffer,
};
use core::cell::RefCell;
use core::future::Future;
use std::rc::Rc;
use std::sync::Mutex;
use std::vec::Vec;

const TEST_DRIVER: u32 = driver_num::LOGGING_FLASH + 1;
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct Driver {
    driver_num: u32,
    allowed: RefCell<RoAllowBuffer>,
    output: RefCell<RwAllowBuffer>,
    share: DriverShareRef,
    records: RefCell<Vec<Vec<u8>>>,
    error: Cell<Option<ErrorCode>>,
    completion_error: Cell<Option<ErrorCode>>,
}

impl Driver {
    fn new(driver_num: u32) -> Self {
        Self {
            driver_num,
            ..Self::default()
        }
    }
}

impl fake::SyscallDriver for Driver {
    fn info(&self) -> DriverInfo {
        DriverInfo::new(self.driver_num).upcall_count(5)
    }

    fn register(&self, share: DriverShareRef) {
        self.share.replace(share);
    }

    fn allow_readonly(
        &self,
        number: u32,
        buffer: RoAllowBuffer,
    ) -> Result<RoAllowBuffer, (RoAllowBuffer, ErrorCode)> {
        assert_eq!(number, ro_allow::APPEND);
        Ok(self.allowed.replace(buffer))
    }

    fn allow_readwrite(
        &self,
        number: u32,
        buffer: RwAllowBuffer,
    ) -> Result<RwAllowBuffer, (RwAllowBuffer, ErrorCode)> {
        assert_eq!(number, rw_allow::READ);
        Ok(self.output.replace(buffer))
    }

    fn command(&self, number: u32, arg1: u32, _arg2: u32) -> CommandReturn {
        if let Some(error) = self.error.take() {
            return command_return::failure(error);
        }
        match number {
            logging_cmd::APPEND => {
                let error = self.completion_error.take().map_or(0, |error| error as u32);
                if error == 0 {
                    self.records
                        .borrow_mut()
                        .push(self.allowed.borrow()[..arg1 as usize].to_vec());
                }
                self.share
                    .schedule_upcall(subscribe::APPEND_DONE, (arg1, 0, error))
                    .unwrap();
                command_return::success()
            }
            logging_cmd::READ => {
                let error = self.completion_error.take().map_or(0, |error| error as u32);
                let length = if error == 0 {
                    self.output.borrow_mut()[..4].copy_from_slice(b"data");
                    4
                } else {
                    0
                };
                self.share
                    .schedule_upcall(subscribe::READ_DONE, (length, error, 0))
                    .unwrap();
                command_return::success()
            }
            logging_cmd::SYNC | logging_cmd::ERASE | logging_cmd::SEEK => {
                let upcall = match number {
                    logging_cmd::SYNC => subscribe::SYNC_DONE,
                    logging_cmd::ERASE => subscribe::ERASE_DONE,
                    _ => subscribe::SEEK_DONE,
                };
                self.share.schedule_upcall(upcall, (0, 0, 0)).unwrap();
                command_return::success()
            }
            _ => command_return::failure(ErrorCode::NoSupport),
        }
    }
}

fn run_ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    for _ in 0..4 {
        if let core::task::Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
        let _ = fake::Syscalls::yield_no_wait();
    }
    panic!("logging future did not complete");
}

fn assert_unsubscribed(driver: &Driver, upcall: u32) {
    assert!(!fake::Kernel::is_upcall_pending());
    driver.share.schedule_upcall(upcall, (0, 0, 0)).unwrap();
    assert!(
        !fake::Kernel::is_upcall_pending(),
        "subscription still registered"
    );
}

#[test]
fn synchronous_append_registers_and_cleans_up_selected_driver() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let driver = Rc::new(Driver::new(TEST_DRIVER));
    kernel.add_driver(&driver);
    let log = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    log.append_entry_sync(b"first").unwrap();
    assert!(driver.allowed.borrow().is_empty());
    assert_unsubscribed(&driver, subscribe::APPEND_DONE);
    driver.error.set(Some(ErrorCode::Busy));
    assert_eq!(log.append_entry_sync(b"rejected"), Err(ErrorCode::Busy));
    assert!(driver.allowed.borrow().is_empty());
    assert_unsubscribed(&driver, subscribe::APPEND_DONE);
    log.append_entry_sync(b"second").unwrap();
    assert_eq!(
        *driver.records.borrow(),
        [b"first".to_vec(), b"second".to_vec()]
    );
}

#[test]
fn asynchronous_append_releases_allow_and_subscription_on_all_completion_paths() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let driver = Rc::new(Driver::new(TEST_DRIVER));
    kernel.add_driver(&driver);
    let log = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    for (immediate, completion, expected) in [
        (Some(ErrorCode::Busy), None, Err(ErrorCode::Busy)),
        (None, Some(ErrorCode::Fail), Err(ErrorCode::Fail)),
        (None, None, Ok(())),
    ] {
        driver.error.set(immediate);
        driver.completion_error.set(completion);
        assert_eq!(run_ready(log.append_entry(b"record")), expected);
        assert!(driver.allowed.borrow().is_empty());
        assert_unsubscribed(&driver, subscribe::APPEND_DONE);
    }
    assert_eq!(*driver.records.borrow(), [b"record".to_vec()]);
}

#[test]
fn asynchronous_read_releases_allow_and_subscription_on_all_completion_paths() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let driver = Rc::new(Driver::new(TEST_DRIVER));
    kernel.add_driver(&driver);
    let log = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    let mut output = [0; 8];
    for (immediate, completion, expected) in [
        (Some(ErrorCode::Busy), None, Err(ErrorCode::Busy)),
        (None, Some(ErrorCode::Fail), Err(ErrorCode::Fail)),
        (None, None, Ok(4)),
    ] {
        driver.error.set(immediate);
        driver.completion_error.set(completion);
        assert_eq!(run_ready(log.read_entry(&mut output)), expected);
        assert!(driver.output.borrow().is_empty());
        assert_unsubscribed(&driver, subscribe::READ_DONE);
    }
    assert_eq!(&output[..4], b"data");
}

#[test]
fn asynchronous_control_rejections_return_errors_and_allow_later_commands() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let driver = Rc::new(Driver::new(TEST_DRIVER));
    kernel.add_driver(&driver);
    let log = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    driver.error.set(Some(ErrorCode::NoSupport));
    assert_eq!(run_ready(log.sync()), Err(ErrorCode::NoSupport));
    for error in [ErrorCode::Busy, ErrorCode::Fail] {
        driver.error.set(Some(error));
        assert_eq!(run_ready(log.clear()), Err(error));
        driver.error.set(Some(error));
        assert_eq!(run_ready(log.seek_beginning()), Err(error));
    }
    assert_eq!(run_ready(log.sync()), Ok(()));
    assert_eq!(run_ready(log.clear()), Ok(()));
    assert_eq!(run_ready(log.seek_beginning()), Ok(()));
    log.append_entry_sync(b"still-usable").unwrap();
}

#[test]
fn default_routes_appends_to_configured_driver_and_explicit_selection_is_independent() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let selected = Rc::new(Driver::new(caliptra_mcu_config::DEFAULT_LOGGING_DRIVER_NUM));
    let explicit = Rc::new(Driver::new(TEST_DRIVER));
    kernel.add_driver(&selected);
    kernel.add_driver(&explicit);

    let log = LoggingSyscall::<fake::Syscalls>::default();
    log.append_entry_sync(b"default sync").unwrap();
    run_ready(log.append_entry(b"default async")).unwrap();
    LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER)
        .append_entry_sync(b"explicit partition")
        .unwrap();

    assert_eq!(
        *selected.records.borrow(),
        [b"default sync".to_vec(), b"default async".to_vec()]
    );
    assert_eq!(*explicit.records.borrow(), [b"explicit partition".to_vec()]);
    assert!(selected.allowed.borrow().is_empty());
    assert_unsubscribed(&selected, subscribe::APPEND_DONE);
}

#[test]
fn unavailable_default_returns_error_without_using_another_partition() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let other_num = if caliptra_mcu_config::DEFAULT_LOGGING_DRIVER_NUM
        == caliptra_mcu_config::LOGGING_FLASH_DRIVER_NUM
    {
        caliptra_mcu_config::LOGGING_RAM_DRIVER_NUM
    } else {
        caliptra_mcu_config::LOGGING_FLASH_DRIVER_NUM
    };
    let other = Rc::new(Driver::new(other_num));
    kernel.add_driver(&other);
    let log = LoggingSyscall::<fake::Syscalls>::default();
    assert_eq!(log.append_entry_sync(b"missing"), Err(ErrorCode::NoDevice));
    assert_eq!(
        run_ready(log.append_entry(b"missing")),
        Err(ErrorCode::NoDevice)
    );
    assert!(other.records.borrow().is_empty());
    LoggingSyscall::<fake::Syscalls>::new(other_num)
        .append_entry_sync(b"explicit")
        .unwrap();
    assert_eq!(*other.records.borrow(), [b"explicit".to_vec()]);
}

#[test]
fn clear_owns_its_slot_until_cleanup_even_after_the_upcall() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let driver = Rc::new(Driver::new(TEST_DRIVER));
    kernel.add_driver(&driver);
    let first = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    let second = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    let mut pending = core::pin::pin!(first.clear());
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());

    assert!(pending.as_mut().poll(&mut context).is_pending());
    assert_eq!(run_ready(second.clear()), Err(ErrorCode::Busy));
    assert!(fake::Kernel::is_upcall_pending());
    let _ = fake::Syscalls::yield_no_wait();
    assert!(!fake::Kernel::is_upcall_pending());

    // A's callback ran, but A has not resumed to clean up its registration.
    assert_eq!(run_ready(second.clear()), Err(ErrorCode::Busy));
    assert_eq!(
        pending.as_mut().poll(&mut context),
        core::task::Poll::Ready(Ok(()))
    );
    assert_eq!(run_ready(second.clear()), Ok(()));
    assert_unsubscribed(&driver, subscribe::ERASE_DONE);
}

#[test]
fn append_ownership_covers_async_and_sync_callers_but_not_other_drivers() {
    let _lock = TEST_LOCK.lock().unwrap();
    let kernel = fake::Kernel::new();
    let driver = Rc::new(Driver::new(TEST_DRIVER));
    let other = Rc::new(Driver::new(TEST_DRIVER + 1));
    kernel.add_driver(&driver);
    kernel.add_driver(&other);
    let first = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    let second = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER);
    let independent = LoggingSyscall::<fake::Syscalls>::new(TEST_DRIVER + 1);
    let mut pending = core::pin::pin!(first.append_entry(b"owner"));
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());

    assert!(pending.as_mut().poll(&mut context).is_pending());
    assert_eq!(second.append_entry_sync(b"sync"), Err(ErrorCode::Busy));
    assert_eq!(
        run_ready(second.append_entry(b"async")),
        Err(ErrorCode::Busy)
    );
    assert_eq!(&driver.allowed.borrow()[..], b"owner");
    run_ready(independent.append_entry(b"independent")).unwrap();
    // Completing a different driver also delivered the first driver's upcall.
    assert_eq!(
        second.append_entry_sync(b"still busy"),
        Err(ErrorCode::Busy)
    );
    assert_eq!(
        pending.as_mut().poll(&mut context),
        core::task::Poll::Ready(Ok(()))
    );
    second.append_entry_sync(b"after cleanup").unwrap();
    assert_eq!(
        *driver.records.borrow(),
        [b"owner".to_vec(), b"after cleanup".to_vec()]
    );
    assert_eq!(*other.records.borrow(), [b"independent".to_vec()]);
}
