// Licensed under the Apache-2.0 license

// Test flash storage driver read, write and erase on arbitrary length of data.

use core::cell::RefCell;
use core::cmp;
use core::fmt::Write;
use flash_driver::{flash_ctrl, flash_storage_to_pages::FlashStorageToPages, hil::FlashStorage};
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

pub const TEST_BUF_LEN: usize = 4096;

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

macro_rules! static_init_fs_test_cb {
    ($buf_len:expr) => {{
        let read_in_buf = static_buf!([u8; $buf_len]).write([0u8; $buf_len]) as &'static mut [u8];
        let write_in_buf =
            static_buf!([u8; $buf_len]).write([0u8; $buf_len]) as &'static mut [u8];

        let mut val: u8 = 0;
        for i in 0..$buf_len {
            val = val.wrapping_add(0x10);
            write_in_buf[i] = val;
        }

        static_init!(
            FlashStorageTestCallBack,
            FlashStorageTestCallBack::new(read_in_buf, write_in_buf)
        )
    }};
}

pub(crate) fn test_flash_storage_erase() -> Option<u32> {
    println!("Starting flash storage erase test");
    let chip = unsafe { crate::CHIP.unwrap() };
    let flash_ctrl = &chip.peripherals.flash_ctrl;
    let flash_storage_drv = unsafe {
        static_init!(
            FlashStorageToPages<flash_ctrl::EmulatedFlashCtrl>,
            FlashStorageToPages::new(
                flash_ctrl,
                static_init!(
                    flash_ctrl::EmulatedFlashPage,
                    flash_ctrl::EmulatedFlashPage::default()
                )
            )
        )
    };
    // Flash storage logical driver is the client of phyiscal flash ctrl driver
    flash_ctrl.set_client(flash_storage_drv);
    let test_cb = unsafe { static_init_fs_test_cb!(TEST_BUF_LEN) };
    // Test callback is the client of flash storage driver
    flash_storage_drv.set_client(test_cb);

    {
        // Test non-page-aligned erase operation.
        let length: usize = 4000;
        let offset: usize = 200;

        assert!(flash_storage_drv.erase(offset, length).is_ok());

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().erase_bytes, length);

        test_cb.reset();
        let read_in_buf = test_cb.read_in_buf.take().unwrap();
        assert!(flash_storage_drv.read(read_in_buf, offset, length).is_ok());

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().read_bytes, length);

        let read_out = test_cb.read_out_buf.take().unwrap();
        // Check if the read_out_buf is filled with 0xFF
        for i in 0..length {
            assert_eq!(read_out[i], 0xffu8, "[ERR] Data mismatch at byte {}", i);
        }
    }
    Some(0)
}

pub(crate) fn test_flash_storage_read_write() -> Option<u32> {
    println!("Starting flash storage read write test");
    let chip = unsafe { crate::CHIP.unwrap() };
    let flash_ctrl = &chip.peripherals.flash_ctrl;
    let flash_storage_drv = unsafe {
        static_init!(
            FlashStorageToPages<flash_ctrl::EmulatedFlashCtrl>,
            FlashStorageToPages::new(
                flash_ctrl,
                static_init!(
                    flash_ctrl::EmulatedFlashPage,
                    flash_ctrl::EmulatedFlashPage::default()
                )
            )
        )
    };
    // Flash storage logical driver is the client of phyiscal flash ctrl driver
    flash_ctrl.set_client(flash_storage_drv);
    let test_cb = unsafe { static_init_fs_test_cb!(TEST_BUF_LEN) };
    // Test callback is the client of flash storage driver
    flash_storage_drv.set_client(test_cb);

    {
        let length: usize = 4000;
        let offset: usize = 200;
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
    Some(0)
}
