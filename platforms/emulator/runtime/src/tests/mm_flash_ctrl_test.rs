// Licensed under the Apache-2.0 license

// Test flash controller driver read, write, erage page

use core::cell::RefCell;
//use flash_driver::flash_ctrl;
use crate::board::run_kernel_op;
use crate::tests::run_kernel_op_with_timeout;
use core::fmt::Write;
use flash_driver::mm_flash_ctrl;
use kernel::hil;
use kernel::hil::flash::{Flash, HasClient};
use kernel::static_init;
use kernel::utilities::cells::TakeCell;
use romtime::println;
pub const TIME_OUT_LIMIT: usize = 10000; // Timeout limit in kernel op iterations

pub struct IoState {
    read_pending: bool,
    write_pending: bool,
    erase_pending: bool,
    op_error: bool,
}

// Create flash callback struct for testing
struct FlashCtrlTestCallBack {
    io_state: RefCell<IoState>,
    read_in_page: TakeCell<'static, mm_flash_ctrl::EmulatedFlashPage>,
    write_in_page: TakeCell<'static, mm_flash_ctrl::EmulatedFlashPage>,
    read_out_buf: TakeCell<'static, [u8]>,
    write_out_buf: TakeCell<'static, [u8]>,
}

impl<'a> FlashCtrlTestCallBack {
    pub fn new(
        read_in_page: &'static mut mm_flash_ctrl::EmulatedFlashPage,
        write_in_page: &'static mut mm_flash_ctrl::EmulatedFlashPage,
    ) -> Self {
        Self {
            io_state: RefCell::new(IoState {
                read_pending: false,
                write_pending: false,
                erase_pending: false,
                op_error: false,
            }),
            read_in_page: TakeCell::new(read_in_page),
            write_in_page: TakeCell::new(write_in_page),
            read_out_buf: TakeCell::empty(),
            write_out_buf: TakeCell::empty(),
        }
    }

    pub fn reset(&self) {
        *self.io_state.borrow_mut() = IoState {
            read_pending: false,
            write_pending: false,
            erase_pending: false,
            op_error: false,
        };
    }
}

impl<'a, F: hil::flash::Flash> hil::flash::Client<F> for FlashCtrlTestCallBack {
    fn read_complete(&self, page: &'static mut F::Page, error: Result<(), hil::flash::Error>) {
        romtime::println!("[xs debug]FlashCtrlTestCallBack: read_complete");
        if self.io_state.borrow().read_pending {
            if let Err(_) = error {
                self.io_state.borrow_mut().op_error = true;
            } else {
                self.read_out_buf.replace(page.as_mut());
            }
            self.io_state.borrow_mut().read_pending = false;
        }
    }

    fn write_complete(&self, page: &'static mut F::Page, error: Result<(), hil::flash::Error>) {
        romtime::println!("[xs debug]FlashCtrlTestCallBack: write_complete");
        if self.io_state.borrow().write_pending {
            if let Err(_) = error {
                self.io_state.borrow_mut().op_error = true;
            } else {
                self.write_out_buf.replace(page.as_mut());
            }
            self.io_state.borrow_mut().write_pending = false;
        }
    }

    fn erase_complete(&self, error: Result<(), hil::flash::Error>) {
        romtime::println!("[xs debug]FlashCtrlTestCallBack: erase_complete");
        if self.io_state.borrow().erase_pending {
            if let Err(_) = error {
                self.io_state.borrow_mut().op_error = true;
            }
            self.io_state.borrow_mut().erase_pending = false;
        }
    }
}

macro_rules! static_init_test {
    () => {{
        let r_in_page = static_init!(
            mm_flash_ctrl::EmulatedFlashPage,
            mm_flash_ctrl::EmulatedFlashPage::default()
        );
        let w_in_page = static_init!(
            mm_flash_ctrl::EmulatedFlashPage,
            mm_flash_ctrl::EmulatedFlashPage::default()
        );
        let mut val: u8 = 0;
        for i in 0..mm_flash_ctrl::PAGE_SIZE {
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

fn test_single_flash_ctrl_erase_page(
    flash_ctrl: &'static mm_flash_ctrl::MailboxFlashCtrl,
    test_cb: &'static FlashCtrlTestCallBack,
) {
    flash_ctrl.set_client(test_cb);
    test_cb.reset();

    let page_num: usize = 15;
    // Test erase page
    assert!(flash_ctrl.erase_page(page_num).is_ok());
    test_cb.io_state.borrow_mut().erase_pending = true;

    let completed =
        run_kernel_op_with_timeout(TIME_OUT_LIMIT, || !test_cb.io_state.borrow().erase_pending);
    assert!(completed, "Timeout waiting for erase operation to complete");

    test_cb.reset();
    // Read the erased page to verify the erase operation
    let read_in_page = test_cb.read_in_page.take().unwrap();
    assert!(flash_ctrl.read_page(page_num, read_in_page).is_ok());
    test_cb.io_state.borrow_mut().read_pending = true;

    let completed =
        run_kernel_op_with_timeout(TIME_OUT_LIMIT, || !test_cb.io_state.borrow().read_pending);
    assert!(completed, "Timeout waiting for read operation to complete");
    assert!(!test_cb.io_state.borrow().op_error);

    // Check if the read_out_buf is filled with 0xFF
    let read_out = test_cb.read_out_buf.take().unwrap();
    assert!(read_out.iter().all(|&x| x == 0xFF));
}

pub(crate) fn test_flash_ctrl_erase_page() -> Option<u32> {
    let chip = unsafe { crate::CHIP.unwrap() };
    let mm_flash_ctrl = &chip.peripherals.mm_flash_ctrl;

    println!("Starting erase page test on MM_FLASH_CTRL");
    let test_cb_main = unsafe { static_init_test!() };
    test_single_flash_ctrl_erase_page(mm_flash_ctrl, test_cb_main);
    println!("Erase page test on MM_FLASH_CTRL PASS");
    Some(0)
}

fn test_single_flash_ctrl_read_write_page(
    flash_ctrl: &'static mm_flash_ctrl::MailboxFlashCtrl,
    test_cb: &'static FlashCtrlTestCallBack,
) {
    flash_ctrl.set_client(test_cb);
    test_cb.reset();

    let page_num: usize = 20;
    let write_in_page = test_cb.write_in_page.take().unwrap();
    assert!(flash_ctrl.write_page(page_num, write_in_page).is_ok());
    test_cb.io_state.borrow_mut().write_pending = true;

    let completed =
        run_kernel_op_with_timeout(TIME_OUT_LIMIT, || !test_cb.io_state.borrow().write_pending);
    assert!(completed, "Timeout waiting for write operation to complete");

    test_cb.reset();

    let read_in_page = test_cb.read_in_page.take().unwrap();
    assert!(flash_ctrl.read_page(page_num, read_in_page).is_ok());
    test_cb.io_state.borrow_mut().read_pending = true;

    let completed =
        run_kernel_op_with_timeout(TIME_OUT_LIMIT, || !test_cb.io_state.borrow().read_pending);
    assert!(completed, "Timeout waiting for read operation to complete");

    // Compare the contents of read/write buffer
    let write_in = test_cb.write_out_buf.take().unwrap();
    let read_out = test_cb.read_out_buf.take().unwrap();

    assert_eq!(write_in.len(), read_out.len());
    assert!(
        write_in.iter().zip(read_out.iter()).all(|(i, j)| i == j),
        "[ERR] Read data indicates flash write error on page {}",
        page_num
    );
}

pub(crate) fn test_flash_ctrl_read_write_page() -> Option<u32> {
    let chip = unsafe { crate::CHIP.unwrap() };
    let mm_flash_ctrl = &chip.peripherals.mm_flash_ctrl;

    println!("[xs debug]Starting read write page test on MM_FLASH_CTRL");
    let test_cb_main = unsafe { static_init_test!() };
    test_single_flash_ctrl_read_write_page(mm_flash_ctrl, test_cb_main);

    println!("[xs debug]Read write page test on MM_FLASH_CTRL PASS");
    Some(0)
}
