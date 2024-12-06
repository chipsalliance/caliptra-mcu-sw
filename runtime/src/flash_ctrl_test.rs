// Test flash controller driver read, write, erage page

use crate::flash_ctrl;
use core::cell::Cell;
use kernel::hil;
use kernel::hil::flash::Flash;
use kernel::hil::flash::HasClient;
use kernel::static_init;
use kernel::utilities::cells::TakeCell;
use kernel::{debug, debug_flush_queue};

use crate::board::run_kernel_op;

fn success() -> ! {
    debug_flush_queue!();
    crate::io::exit_emulator(0);
}

#[allow(dead_code)]
fn fail() -> ! {
    debug_flush_queue!();
    crate::io::exit_emulator(1);
}



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
    read_out_buf: TakeCell<'static, [u8]>,
    write_out_buf: TakeCell<'static, [u8]>,
}

impl<'a> FlashCtrlTestCallBack {
    pub fn new() -> FlashCtrlTestCallBack {
        FlashCtrlTestCallBack {
            read_pending: Cell::new(false),
            write_pending: Cell::new(false),
            read_out_buf: TakeCell::empty(),
            write_out_buf: TakeCell::empty(),
        }
    }

    pub fn reset(&self) {
        self.read_pending.set(false);
        self.write_pending.set(false);
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

            debug!("[xs debug]callback: write_complete");
            debug_flush_queue!();

        }
    }

    fn erase_complete(&self, error: Result<(), hil::flash::Error>) {
        // Caller may check by a successive page read to assert the erased
        // page is composed of 0xFF (all erased bits should be 1)
        assert_eq!(error, Ok(()));
    }
}

// Set up the test for write page and read back to compare the data
pub(crate) fn test_flash_ctrl_read_write_page() -> Option<u32> {
    debug!("[xs debug] Starting flash controller read write page test");
    debug_flush_queue!();

    // run_kernel_op(5000);

    let chip = unsafe { crate::CHIP.unwrap() };

    let flash_ctrl = &chip.peripherals.flash_ctrl;

    let test_cb = unsafe { static_init!(FlashCtrlTestCallBack, FlashCtrlTestCallBack::new()) };

    // Set up the client
    flash_ctrl.set_client(test_cb);

    test_cb.reset();

    let page_num: usize = 19;

    // run_kernel_op(5000);

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

    debug!(
        "[xs debug]write_page_buf_test addr = {:p}",
        write_page_buf_test.0.as_ptr()
    );
    debug_flush_queue!();

    // run_kernel_op(50000);


    assert!(flash_ctrl.write_page(page_num, write_page_buf_test).is_ok());

    test_cb.write_pending.set(true);

    // run_kernel_op(5000_00);

    // OP Complete
    assert_eq!(test_cb.write_pending.get(), false);

    // Print out the write_out_buf contents
    debug!("[xs debug]write_out_buf contents:");
    for i in 0..flash_ctrl::PAGE_SIZE {
        debug!("{:x}", test_cb.write_out_buf.map(|buf| buf[i]).unwrap());
    }
    debug_flush_queue!();

    // run_kernel_op(5000);

    None

    /*
    // Check the data written to the page
    let read_page_buf_test = unsafe {
        static_init!(
            flash_ctrl::EmulatedFlashPage,
            flash_ctrl::EmulatedFlashPage::default()
        )
    };

    assert!(flash_ctrl.read_page(page_num, read_page_buf_test).is_ok());

    test_cb.read_pending.set(true);

    // // run_kernel_op(100);

    // OP Complete, buffer recovered.
    assert!(!test_cb.read_pending.get());

    // Compare read_out_buf with write_out_buf to check if the data is written correctly
    for i in 0..flash_ctrl::PAGE_SIZE {
        assert_eq!(
            test_cb.read_out_buf.map(|buf| buf[i]),
            test_cb.write_out_buf.map(|buf| buf[i])
        );
    }

    test_cb.reset(); */


}
