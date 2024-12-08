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
    feature = "test-flash-ctrl-write-page"
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
    read_out_buf: TakeCell<'static, [u8]>,
    write_out_buf: TakeCell<'static, [u8]>,
}

impl<'a> FlashCtrlTestCallBack {
    pub fn new() -> FlashCtrlTestCallBack {
        FlashCtrlTestCallBack {
            read_pending: Cell::new(false),
            write_pending: Cell::new(false),
            erase_pending: Cell::new(false),
            read_out_buf: TakeCell::empty(),
            write_out_buf: TakeCell::empty(),
        }
    }

    pub fn reset(&self) {
        self.read_pending.set(false);
        self.write_pending.set(false);
        self.erase_pending.set(false);
    }
}

impl<'a, F: hil::flash::Flash> hil::flash::Client<F> for FlashCtrlTestCallBack {
    fn read_complete(&self, page: &'static mut F::Page, error: Result<(), hil::flash::Error>) {
        if self.read_pending.get() {
            assert_eq!(error, Ok(()));
            self.read_out_buf.replace(page.as_mut());
            self.read_pending.set(false);
        }
    }

    fn write_complete(&self, page: &'static mut F::Page, error: Result<(), hil::flash::Error>) {
        if self.write_pending.get() {
            assert_eq!(error, Ok(()));
            self.write_out_buf.replace(page.as_mut());
            self.write_pending.set(false);
            println!("[xs debug]callback: write_complete");
        }
    }

    fn erase_complete(&self, error: Result<(), hil::flash::Error>) {
        // Caller may check by a successive page read to assert the erased
        // page is composed of 0xFF (all erased bits should be 1)
        if self.erase_pending.get() {
            assert_eq!(error, Ok(()));
            self.erase_pending.set(false);
            println!("[xs debug]callback: erase_complete");
        }
    }
}

pub fn test_flash_ctrl_erase_page() -> Option<u32> {
    println!("[xs debug]test: Starting flash controller erase page test");

    let chip = unsafe { crate::CHIP.unwrap() };

    let flash_ctrl = &chip.peripherals.flash_ctrl;
    chip.peripherals.flash_ctrl.init();

    let test_cb = unsafe { static_init!(FlashCtrlTestCallBack, FlashCtrlTestCallBack::new()) };

    // Set up the client
    flash_ctrl.set_client(test_cb);

    test_cb.reset();

    let page_num: usize = 10;

    assert!(flash_ctrl.erase_page(page_num).is_ok());
    test_cb.erase_pending.set(true);

    #[cfg(feature = "test-flash-ctrl-erase-page")]
    run_kernel_op(100);

    assert!(!test_cb.write_pending.get());

    Some(0)
}

// Set up the test for write page operation
pub(crate) fn test_flash_ctrl_write_page() -> Option<u32> {
    println!("[xs debug]test: Starting flash controller read write page test");

    let chip = unsafe { crate::CHIP.unwrap() };

    let flash_ctrl = &chip.peripherals.flash_ctrl;

    let test_cb = unsafe { static_init!(FlashCtrlTestCallBack, FlashCtrlTestCallBack::new()) };

    // Set up the client
    flash_ctrl.set_client(test_cb);

    test_cb.reset();

    // Test write page
    let page_num: usize = 5;

    // Construct page write buffer with arbitrary data
    let write_page_buf_test = unsafe {
        static_init!(
            flash_ctrl::EmulatedFlashPage,
            flash_ctrl::EmulatedFlashPage::default()
        )
    };

    for i in 0..flash_ctrl::PAGE_SIZE {
        write_page_buf_test[i] = 0xBB; // Arbitrary Data
    }

    println!(
        "[xs debug]test: write_page_buf_test addr = {:p}",
        write_page_buf_test.0.as_ptr()
    );

    // Test driver write page operation
    assert!(flash_ctrl.write_page(page_num, write_page_buf_test).is_ok());
    test_cb.write_pending.set(true);

    // Run the kernel operation and wait for interrupt handler to be called
    #[cfg(feature = "test-flash-ctrl-write-page")]
    run_kernel_op(500000);

    // Check if the write operation is completed
    assert_eq!(test_cb.write_pending.get(), false);

    Some(0)
}
