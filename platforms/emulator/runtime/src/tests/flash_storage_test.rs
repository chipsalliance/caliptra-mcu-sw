// Licensed under the Apache-2.0 license

// Test flash storage driver read, write and erase on arbitrary length of data.

use core::cell::RefCell;
use core::cmp;
use core::fmt::Write;
use flash_driver::{flash_storage_to_pages::FlashStorageToPages, hil::FlashStorage};
use kernel::hil::flash::HasClient;
use kernel::utilities::cells::TakeCell;
use kernel::{static_buf, static_init};
use romtime::println;

#[cfg(any(
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
use crate::board::run_kernel_op;

pub const TEST_BUF_LEN: usize = 2048;

pub struct IoState {
    read_bytes: usize,
    write_bytes: usize,
    erase_bytes: usize,
}

struct FlashStorageTestCallBack {
    io_state: RefCell<IoState>,
    read_in_buf: TakeCell<'static, [u8]>,
    write_in_buf: TakeCell<'static, [u8]>,
    read_out_buf: TakeCell<'static, [u8]>,
    write_out_buf: TakeCell<'static, [u8]>,
}

impl FlashStorageTestCallBack {
    pub fn new(read_in_buf: &'static mut [u8], write_in_buf: &'static mut [u8]) -> Self {
        Self {
            io_state: RefCell::new(IoState {
                read_bytes: 0u8 as usize,
                write_bytes: 0u8 as usize,
                erase_bytes: 0u8 as usize,
            }),
            read_in_buf: TakeCell::new(read_in_buf),
            write_in_buf: TakeCell::new(write_in_buf),
            read_out_buf: TakeCell::empty(),
            write_out_buf: TakeCell::empty(),
        }
    }

    pub fn reset(&self) {
        *self.io_state.borrow_mut() = IoState {
            read_bytes: 0,
            write_bytes: 0,
            erase_bytes: 0,
        };
    }
}

impl flash_driver::hil::FlashStorageClient for FlashStorageTestCallBack {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {
        self.read_out_buf.replace(buffer);
        self.io_state.borrow_mut().read_bytes = length;
    }

    fn write_done(&self, buffer: &'static mut [u8], length: usize) {
        self.write_out_buf.replace(buffer);
        self.io_state.borrow_mut().write_bytes = length;
    }

    fn erase_done(&self, length: usize) {
        self.io_state.borrow_mut().erase_bytes = length;
    }
}

macro_rules! static_init_fs_test {
    ($flash_ctrl:expr, $buf_len:expr) => {{
        let fs_drv = static_init!(
            FlashStorageToPages<flash_ctrl_emulator::EmulatedFlashCtrl>,
            FlashStorageToPages::new(
                $flash_ctrl,
                static_init!(
                    flash_ctrl_emulator::EmulatedFlashPage,
                    flash_ctrl_emulator::EmulatedFlashPage::default()
                )
            )
        );

        let read_in_buf = static_buf!([u8; $buf_len]).write([0u8; $buf_len]) as &'static mut [u8];
        let write_in_buf =
            static_buf!([u8; $buf_len]).write([0u8; $buf_len]) as &'static mut [u8];

        let mut val: u8 = 0;
        for i in 0..$buf_len {
            val = val.wrapping_add(0x10);
            write_in_buf[i] = val;
        }

        let test_cb = static_init!(
            FlashStorageTestCallBack,
            FlashStorageTestCallBack::new(read_in_buf, write_in_buf)
        );
        (fs_drv, test_cb)
    }};
}

fn test_single_flash_storage_erase(
    flash_storage_drv: &'static FlashStorageToPages<flash_ctrl_emulator::EmulatedFlashCtrl>,
    test_cb: &'static FlashStorageTestCallBack,
) {
    flash_storage_drv.set_client(test_cb);

    {
        // Erase the entire test range [0..TEST_BUF_LEN)
        let erase_len = TEST_BUF_LEN;
        test_cb.reset();
        assert!(flash_storage_drv.erase(0, erase_len).is_ok());

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().erase_bytes, erase_len);
        test_cb.reset();

        // Start writing data to the entire test range [0..TEST_BUF_LEN)
        let write_in_buf = test_cb.write_in_buf.take().unwrap();
        assert!(flash_storage_drv
            .write(write_in_buf, 0, TEST_BUF_LEN)
            .is_ok());

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(5000);

        assert_eq!(test_cb.io_state.borrow().write_bytes, TEST_BUF_LEN);

        // Get the write buffer to compare with the read buffer later
        let write_out_buf = test_cb.write_out_buf.take().unwrap();

        test_cb.reset();

        // Test non-page-aligned erase operation.
        // Make sure it is within the test range of [0..TEST_BUF_LEN) that is written to flash.
        let length: usize = 1600;
        let offset: usize = 50;

        assert!(flash_storage_drv.erase(offset, length).is_ok());

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().erase_bytes, length);
        test_cb.reset();

        // Read the entire test range to verify data integrity after erase operation.
        let read_in_buf = test_cb.read_in_buf.take().unwrap();
        assert!(flash_storage_drv.read(read_in_buf, 0, erase_len).is_ok());

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().read_bytes, erase_len);

        let read_out_buf = test_cb.read_out_buf.take().unwrap();
        for i in 0..erase_len {
            if i >= offset && i < offset + length {
                assert_eq!(read_out_buf[i], 0xFFu8, "[ERR] Data mismatch at byte {}", i);
            } else {
                assert_eq!(
                    read_out_buf[i], write_out_buf[i],
                    "[ERR] Data mismatch at byte {}",
                    i
                );
            }
        }
    }
}

pub fn test_flash_storage_erase() -> Option<u32> {
    let peripherals: &'static crate::interrupts::EmulatorPeripherals<'static> =
        unsafe { crate::EMULATOR_PERIPHERALS.unwrap() };
    println!("Starting flash storage erase test on main flash controller");
    let primary_flash_ctrl = &peripherals.primary_flash_ctrl;
    let (fs_drv_main, test_cb_main) =
        unsafe { static_init_fs_test!(primary_flash_ctrl, TEST_BUF_LEN) };
    primary_flash_ctrl.set_client(fs_drv_main);
    test_single_flash_storage_erase(fs_drv_main, test_cb_main);

    println!("Starting flash storage erase test on recovery flash controller");
    let secondary_flash_ctrl = &peripherals.secondary_flash_ctrl;
    let (fs_drv_recovery, test_cb_recovery) =
        unsafe { static_init_fs_test!(secondary_flash_ctrl, TEST_BUF_LEN) };
    secondary_flash_ctrl.set_client(fs_drv_recovery);
    test_single_flash_storage_erase(fs_drv_recovery, test_cb_recovery);

    Some(0)
}

fn test_single_flash_storage_read_write(
    flash_storage_drv: &'static FlashStorageToPages<flash_ctrl_emulator::EmulatedFlashCtrl>,
    test_cb: &'static FlashStorageTestCallBack,
) {
    flash_storage_drv.set_client(test_cb);

    {
        // Erase first
        let erase_len = TEST_BUF_LEN;
        test_cb.reset();
        assert!(flash_storage_drv.erase(0, erase_len).is_ok());

        #[cfg(feature = "test-flash-storage-read-write")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().erase_bytes, erase_len);
        test_cb.reset();

        // Non-page-aligned write operation.
        // Make sure it is within the range of [0.. TEST_BUF_LEN) that is erased.
        let length: usize = 4000;
        let offset: usize = 50;
        let write_in_buf = test_cb.write_in_buf.take().unwrap();

        assert!(flash_storage_drv
            .write(write_in_buf, offset, cmp::min(length, TEST_BUF_LEN))
            .is_ok());

        #[cfg(feature = "test-flash-storage-read-write")]
        run_kernel_op(2000);

        let write_bytes = test_cb.io_state.borrow().write_bytes;
        // Check if the write operation is completed
        assert_eq!(write_bytes, cmp::min(length, TEST_BUF_LEN));

        test_cb.reset();

        // Read the written data to verify the write operation
        let read_in_buf = test_cb.read_in_buf.take().unwrap();
        assert!(flash_storage_drv
            .read(read_in_buf, offset, cmp::min(length, TEST_BUF_LEN))
            .is_ok());

        #[cfg(feature = "test-flash-storage-read-write")]
        run_kernel_op(2000);

        assert_eq!(
            test_cb.io_state.borrow().read_bytes,
            cmp::min(length, TEST_BUF_LEN)
        );

        let read_bytes = test_cb.io_state.borrow().read_bytes;
        assert_eq!(write_bytes, read_bytes);

        // Compare the contents of read/write buffer
        let write_in = test_cb.write_out_buf.take().unwrap();
        let read_out = test_cb.read_out_buf.take().unwrap();
        for i in 0..write_bytes {
            assert_eq!(
                write_in[i], read_out[i],
                "[ERR] Data mismatch at byte {}",
                i
            );
        }
    }
}

pub(crate) fn test_flash_storage_read_write() -> Option<u32> {
    let peripherals = unsafe { crate::EMULATOR_PERIPHERALS.unwrap() };
    println!("Starting flash storage read write test on main flash controller");
    let primary_flash_ctrl = &peripherals.primary_flash_ctrl;
    let (fs_drv_main, test_cb_main) =
        unsafe { static_init_fs_test!(primary_flash_ctrl, TEST_BUF_LEN) };
    primary_flash_ctrl.set_client(fs_drv_main);
    test_single_flash_storage_read_write(fs_drv_main, test_cb_main);

    println!("Starting flash storage read write test on recovery flash controller");
    let secondary_flash_ctrl = &peripherals.secondary_flash_ctrl;
    let (fs_drv_recovery, test_cb_recovery) =
        unsafe { static_init_fs_test!(secondary_flash_ctrl, TEST_BUF_LEN) };
    secondary_flash_ctrl.set_client(fs_drv_recovery);
    test_single_flash_storage_read_write(fs_drv_recovery, test_cb_recovery);

    Some(0)
}
