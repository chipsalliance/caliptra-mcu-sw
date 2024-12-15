// Test flash_storage driver read, write, erage arbitrary length of data

use core::cell::{Cell, RefCell};
use core::cmp;

use flash_driver::{flash_ctrl, flash_storage_to_pages, hil::FlashStorage};

use kernel::hil;
use kernel::hil::flash::{Flash, HasClient};
use kernel::utilities::cells::TakeCell;
use kernel::{static_buf, static_init};
//use kernel::{debug, debug_flush_queue};

use core::fmt::Write;
use romtime::println;

#[cfg(any(
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
use crate::board::run_kernel_op;

pub struct IoState {
    read_pending: bool,
    write_pending: bool,
    erase_pending: bool,
    _op_error: bool,
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
                read_pending: false,
                write_pending: false,
                erase_pending: false,
                _op_error: false,
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
            read_pending: false,
            write_pending: false,
            erase_pending: false,
            _op_error: false,
            read_bytes: 0u8 as usize,
            write_bytes: 0u8 as usize,
            erase_bytes: 0u8 as usize,
        };
    }
}

impl flash_driver::hil::FlashStorageClient for FlashStorageTestCallBack {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {
        if self.io_state.borrow().read_pending {
            self.read_out_buf.replace(buffer);
            self.io_state.borrow_mut().read_pending = false;
            self.io_state.borrow_mut().read_bytes = length;
            println!("[xs debug]read_done: {} bytes", length);
        }
    }

    fn write_done(&self, buffer: &'static mut [u8], length: usize) {
        if self.io_state.borrow().write_pending {
            self.write_out_buf.replace(buffer);
            self.io_state.borrow_mut().write_pending = false;
            self.io_state.borrow_mut().write_bytes = length;
            println!("[xs debug]write_done:  {} bytes", length);
        }
    }

    fn erase_done(&self, length: usize) {
        if self.io_state.borrow().erase_pending {
            self.io_state.borrow_mut().erase_pending = false;
            self.io_state.borrow_mut().erase_bytes = length;
            println!("[xs debug]erase_done: {} bytes", length);
        }
    }
}

macro_rules! static_init_fs_test {
    () => {{
        const BUF_LEN: usize = 4096;
        let read_in_buf =
            kernel::static_buf!([u8; BUF_LEN]).write([0u8; BUF_LEN]) as &'static mut [u8];
        let write_in_buf =
            kernel::static_buf!([u8; BUF_LEN]).write([0u8; BUF_LEN]) as &'static mut [u8];

        let mut val: u8 = 0;
        for i in 0..BUF_LEN {
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

    let page_buffer = unsafe {
        static_init!(
            flash_ctrl::EmulatedFlashPage,
            flash_ctrl::EmulatedFlashPage::default()
        )
    };

    // Initiate the flash storage driver
    let flash_storage = unsafe {
        static_init!(
            flash_storage_to_pages::FlashStorageToPages<flash_ctrl::EmulatedFlashCtrl>,
            flash_storage_to_pages::FlashStorageToPages::new(flash_ctrl, page_buffer)
        )
    };

    // Set up the client for flash controller
    flash_ctrl.set_client(flash_storage);

    let test_cb = unsafe { static_init_fs_test!() };
    // Set up the client
    flash_storage.set_client(test_cb);

    test_cb.reset();

    {
        let length: usize = 4000;
        let offset: usize = 200;

        assert!(flash_storage.erase(offset, length).is_ok());
        test_cb.io_state.borrow_mut().erase_pending = true;

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        assert_eq!(test_cb.io_state.borrow().erase_bytes, length);

        // Read the data back to ensure it is all 0xFF

        test_cb.reset();

        let read_in_buf = test_cb.read_in_buf.take().unwrap();
        assert!(flash_storage.read(read_in_buf, offset, length).is_ok());
        test_cb.io_state.borrow_mut().read_pending = true;

        #[cfg(feature = "test-flash-storage-erase")]
        run_kernel_op(2000);

        // Check if the read operation is completed
        assert_eq!(test_cb.io_state.borrow().read_bytes, length);
        let read_out = test_cb.read_out_buf.take().unwrap();

        // Check buffer contents
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

    let page_buffer = unsafe {
        static_init!(
            flash_ctrl::EmulatedFlashPage,
            flash_ctrl::EmulatedFlashPage::default()
        )
    };

    // Initiate the flash storage driver
    let flash_storage = unsafe {
        static_init!(
            flash_storage_to_pages::FlashStorageToPages<flash_ctrl::EmulatedFlashCtrl>,
            flash_storage_to_pages::FlashStorageToPages::new(flash_ctrl, page_buffer)
        )
    };

    // Set up the client for flash controller
    flash_ctrl.set_client(flash_storage);

    let test_cb = unsafe { static_init_fs_test!() };
    // Set up the client
    flash_storage.set_client(test_cb);

    test_cb.reset();

    {
        let length: usize = 4000;
        let offset: usize = 200;

        println!(
            "[xs debug] Starting test flash storage read write: offset: {}, length: {}",
            offset, length
        );

        let write_in_buf = test_cb.write_in_buf.take().unwrap();

        assert!(flash_storage.write(write_in_buf, offset, length).is_ok());
        test_cb.io_state.borrow_mut().write_pending = true;

        #[cfg(feature = "test-flash-storage-read-write")]
        run_kernel_op(2000);

        // Check if the write operation is completed
        assert_eq!(test_cb.io_state.borrow().write_pending, false);

        let write_bytes = test_cb.io_state.borrow().write_bytes;

        test_cb.reset();

        let read_in_buf = test_cb.read_in_buf.take().unwrap();
        assert!(flash_storage.read(read_in_buf, offset, length).is_ok());
        test_cb.io_state.borrow_mut().read_pending = true;

        #[cfg(feature = "test-flash-storage-read-write")]
        run_kernel_op(2000);

        // Check if the read operation is completed
        assert_eq!(test_cb.io_state.borrow().read_pending, false);
        //assert_eq!(test_cb.io_state.borrw().read_bytes, cmp::min(length, read_out_buf.len()))

        let read_bytes = test_cb.io_state.borrow().read_bytes;

        // Compare the contents of read/write buffer
        let write_in = test_cb.write_out_buf.take().unwrap();
        let read_out = test_cb.read_out_buf.take().unwrap();

        assert_eq!(write_bytes, read_bytes);
        // Compare the buffer contents from 0 to write_bytes
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
