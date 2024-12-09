// Licensed under the Apache-2.0 license

// Test flash controller driver read, write, erage page

use crate::flash_ctrl;
use core::cell::Cell;
use kernel::hil;
use kernel::hil::flash::{Flash, HasClient};
use kernel::static_init;
use kernel::utilities::cells::TakeCell;
use kernel::{debug, debug_flush_queue};

#[cfg(any(
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-ctrl-read-write-page"
))]
use crate::board::run_kernel_op;

use core::fmt::Write;
use romtime::println;

pub(crate) fn test_flash_ctrl_init() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    chip.peripherals.flash_ctrl.init();
    Some(0)
}

// Create flash callback struct for testing
struct FlashCtrlTestCallBack {
    read_pending: Cell<bool>,
    write_pending: Cell<bool>,
    erase_pending: Cell<bool>,
    read_in_page: TakeCell<'static, flash_ctrl::EmulatedFlashPage>,
    write_in_page: TakeCell<'static, flash_ctrl::EmulatedFlashPage>,
    read_out_buf: TakeCell<'static, [u8]>,
    write_out_buf: TakeCell<'static, [u8]>,
    op_error: Cell<bool>,
}

impl<'a> FlashCtrlTestCallBack {
    pub fn new(
        read_in_page: &'static mut flash_ctrl::EmulatedFlashPage,
        write_in_page: &'static mut flash_ctrl::EmulatedFlashPage,
    ) -> FlashCtrlTestCallBack {
        FlashCtrlTestCallBack {
            read_pending: Cell::new(false),
            write_pending: Cell::new(false),
            erase_pending: Cell::new(false),
            read_in_page: TakeCell::new(read_in_page),
            write_in_page: TakeCell::new(write_in_page),
            read_out_buf: TakeCell::empty(),
            write_out_buf: TakeCell::empty(),
            op_error: Cell::new(false),
        }
    }

    pub fn reset(&self) {
        self.read_pending.set(false);
        self.write_pending.set(false);
        self.erase_pending.set(false);
        self.op_error.set(false);
    }
}

impl<'a, F: hil::flash::Flash> hil::flash::Client<F> for FlashCtrlTestCallBack {
    fn read_complete(&self, page: &'static mut F::Page, error: Result<(), hil::flash::Error>) {
        if self.read_pending.get() {
            // Check if it is error result. If yes, it must be a flash read error
            if let Err(_) = error {
                self.op_error.set(true);
            } else {
                self.read_out_buf.replace(page.as_mut());
            }
            self.read_pending.set(false);
        }
    }

    fn write_complete(&self, page: &'static mut F::Page, error: Result<(), hil::flash::Error>) {
        if self.write_pending.get() {
            if let Err(_) = error {
                self.op_error.set(true);
            } else {
                self.write_out_buf.replace(page.as_mut());
            }
            self.write_pending.set(false);
            println!("[xs debug]callback: write_complete");
        }
    }

    fn erase_complete(&self, error: Result<(), hil::flash::Error>) {
        // Caller may check by a successive page read to assert the erased
        // page is composed of 0xFF (all erased bits should be 1)
        if self.erase_pending.get() {
            if let Err(_) = error {
                self.op_error.set(true);
            }
            self.erase_pending.set(false);
            println!("[xs debug]callback: erase_complete");
        }
    }
}

macro_rules! static_init_test {
    () => {{
        let r_in_page = static_init!(
            flash_ctrl::EmulatedFlashPage,
            flash_ctrl::EmulatedFlashPage::default()
        );
        let w_in_page = static_init!(
            flash_ctrl::EmulatedFlashPage,
            flash_ctrl::EmulatedFlashPage::default()
        );
        let mut val: u8 = 0;

        for i in 0..flash_ctrl::PAGE_SIZE {
            val = val.wrapping_add(0x10);
            r_in_page[i] = 0x00;
            // Fill the write buffer with arbitrary data
            w_in_page[i] = val;
        }
        static_init!(
            FlashCtrlTestCallBack,
            FlashCtrlTestCallBack::new(r_in_page, w_in_page)
        )
    }};
}

pub fn test_flash_ctrl_erase_page() -> Option<u32> {
    println!("[xs debug]test: Starting flash controller erase page test");

    let chip = unsafe { crate::CHIP.unwrap() };
    let flash_ctrl = &chip.peripherals.flash_ctrl;
    let test_cb = unsafe { static_init_test!() };

    // Set up the client
    flash_ctrl.set_client(test_cb);
    test_cb.reset();

    // Test erase page
    let page_num: usize = 15;

    assert!(flash_ctrl.erase_page(page_num).is_ok());
    test_cb.erase_pending.set(true);

    #[cfg(feature = "test-flash-ctrl-erase-page")]
    run_kernel_op(100);

    // Check if the erase operation is completed
    assert!(!test_cb.erase_pending.get());

    test_cb.reset();

    let read_in_page = test_cb.read_in_page.take().unwrap();
    // Read the erased page to verify the erase operation
    assert!(flash_ctrl.read_page(page_num, read_in_page).is_ok());
    test_cb.read_pending.set(true);

    #[cfg(feature = "test-flash-ctrl-erase-page")]
    run_kernel_op(100);

    // Check if the read operation is completed
    assert!(!test_cb.read_pending.get());

    // Check if the read_out_buf is filled with 0xFF
    let read_out = test_cb.read_out_buf.take().unwrap();
    assert!(read_out.iter().all(|&x| x == 0xFF));

    Some(0)
}

// Set up the test for write page operation
pub(crate) fn test_flash_ctrl_read_write_page() -> Option<u32> {
    println!("[xs debug]test: Starting flash controller read write page test");

    let chip = unsafe { crate::CHIP.unwrap() };
    let flash_ctrl = &chip.peripherals.flash_ctrl;
    let test_cb = unsafe { static_init_test!() };

    // Set up the client
    flash_ctrl.set_client(test_cb);
    test_cb.reset();

    // Test write page
    let page_num: usize = 20;

    let write_in_page = test_cb.write_in_page.take().unwrap();
    assert!(flash_ctrl.write_page(page_num, write_in_page).is_ok());
    test_cb.write_pending.set(true);

    // Run the kernel operation and wait for interrupt handler to be called
    #[cfg(feature = "test-flash-ctrl-read-write-page")]
    run_kernel_op(100);

    // Check if the write operation is completed
    assert_eq!(test_cb.write_pending.get(), false);

    test_cb.reset();

    let read_in_page = test_cb.read_in_page.take().unwrap();
    assert!(flash_ctrl.read_page(page_num, read_in_page).is_ok());
    test_cb.read_pending.set(true);

    // Run the kernel operation and wait for interrupt handler to be called
    #[cfg(feature = "test-flash-ctrl-read-write-page")]
    run_kernel_op(100);

    // Check if the read operation is completed
    assert_eq!(test_cb.read_pending.get(), false);

    // Compare the contents of read/write buffer
    let write_in = test_cb.write_out_buf.take().unwrap();
    let read_out = test_cb.read_out_buf.take().unwrap();

    assert_eq!(write_in.len(), read_out.len());
    assert!(
        write_in.iter().zip(read_out.iter()).all(|(i, j)| i == j),
        "[ERR] Read data indicates flash write error on page {}",
        page_num
    );

    Some(0)
}
