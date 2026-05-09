// Licensed under the Apache-2.0 license

// Test flash controller driver read, write, erage page

use core::cell::RefCell;
use kernel::hil;
use kernel::hil::flash::{Flash, HasClient};
use kernel::static_init;
use kernel::utilities::cells::TakeCell;

#[cfg(any(
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-ctrl-read-write-page"
))]
use crate::board::run_kernel_op;

use core::fmt::Write;
use romtime::println;

pub(crate) fn test_flash_ctrl_init() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let peripherals = unsafe { crate::EMULATOR_PERIPHERALS.unwrap() };
    peripherals.primary_flash_ctrl.init();
    peripherals.secondary_flash_ctrl.init();
    Some(0)
}

pub struct IoState {
    read_pending: bool,
    write_pending: bool,
    erase_pending: bool,
    op_error: bool,
}

// Create flash callback struct for testing
struct FlashCtrlTestCallBack {
    io_state: RefCell<IoState>,
    read_in_page: TakeCell<'static, flash_ctrl_emulator::EmulatedFlashPage>,
    write_in_page: TakeCell<'static, flash_ctrl_emulator::EmulatedFlashPage>,
    read_out_buf: TakeCell<'static, [u8]>,
    write_out_buf: TakeCell<'static, [u8]>,
}

impl<'a> FlashCtrlTestCallBack {
    pub fn new(
        read_in_page: &'static mut flash_ctrl_emulator::EmulatedFlashPage,
        write_in_page: &'static mut flash_ctrl_emulator::EmulatedFlashPage,
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
            flash_ctrl_emulator::EmulatedFlashPage,
            flash_ctrl_emulator::EmulatedFlashPage::default()
        );
        let w_in_page = static_init!(
            flash_ctrl_emulator::EmulatedFlashPage,
            flash_ctrl_emulator::EmulatedFlashPage::default()
        );
        let mut val: u8 = 0;
        for i in 0..flash_ctrl_emulator::PAGE_SIZE {
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
    flash_ctrl: &'static flash_ctrl_emulator::EmulatedFlashCtrl,
    test_cb: &'static FlashCtrlTestCallBack,
) {
    flash_ctrl.set_client(test_cb);
    test_cb.reset();

    let page_num: usize = 15;
    // Test erase page
    assert!(flash_ctrl.erase_page(page_num).is_ok());
    test_cb.io_state.borrow_mut().erase_pending = true;

    #[cfg(feature = "test-flash-ctrl-erase-page")]
    run_kernel_op(100);

    // Check if the erase operation is completed
    assert!(!test_cb.io_state.borrow().erase_pending);

    test_cb.reset();
    // Read the erased page to verify the erase operation
    let read_in_page = test_cb.read_in_page.take().unwrap();
    assert!(flash_ctrl.read_page(page_num, read_in_page).is_ok());
    test_cb.io_state.borrow_mut().read_pending = true;

    #[cfg(feature = "test-flash-ctrl-erase-page")]
    run_kernel_op(100);

    // Check if the read operation is completed
    assert!(!test_cb.io_state.borrow().read_pending);
    assert!(!test_cb.io_state.borrow().op_error);

    // Check if the read_out_buf is filled with 0xFF
    let read_out = test_cb.read_out_buf.take().unwrap();
    assert!(read_out.iter().all(|&x| x == 0xFF));
}

pub fn test_flash_ctrl_erase_page() -> Option<u32> {
    let peripherals = unsafe { crate::EMULATOR_PERIPHERALS.unwrap() };
    println!("Starting erase page test on main flash controller");
    let test_cb_main = unsafe { static_init_test!() };
    test_single_flash_ctrl_erase_page(&peripherals.primary_flash_ctrl, test_cb_main);

    println!("Starting erase page test on recovery flash controller");
    let test_cb_recovery = unsafe { static_init_test!() };
    test_single_flash_ctrl_erase_page(&peripherals.secondary_flash_ctrl, test_cb_recovery);
    Some(0)
}

fn test_single_flash_ctrl_read_write_page(
    flash_ctrl: &'static flash_ctrl_emulator::EmulatedFlashCtrl,
    test_cb: &'static FlashCtrlTestCallBack,
) {
    flash_ctrl.set_client(test_cb);
    test_cb.reset();

    let page_num: usize = 20;
    let write_in_page = test_cb.write_in_page.take().unwrap();
    assert!(flash_ctrl.write_page(page_num, write_in_page).is_ok());
    test_cb.io_state.borrow_mut().write_pending = true;

    // Run the kernel operation and wait for interrupt handler to be called
    #[cfg(feature = "test-flash-ctrl-read-write-page")]
    run_kernel_op(100);

    // Check if the write operation is completed
    assert_eq!(test_cb.io_state.borrow().write_pending, false);

    test_cb.reset();

    let read_in_page = test_cb.read_in_page.take().unwrap();
    assert!(flash_ctrl.read_page(page_num, read_in_page).is_ok());
    test_cb.io_state.borrow_mut().read_pending = true;

    // Run the kernel operation and wait for interrupt handler to be called
    #[cfg(feature = "test-flash-ctrl-read-write-page")]
    run_kernel_op(100);

    // Check if the read operation is completed
    assert_eq!(test_cb.io_state.borrow().read_pending, false);

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
    let peripherals = unsafe { crate::EMULATOR_PERIPHERALS.unwrap() };
    println!("Starting read write page test on main flash controller");
    let test_cb_main = unsafe { static_init_test!() };
    test_single_flash_ctrl_read_write_page(&peripherals.primary_flash_ctrl, test_cb_main);

    println!("Starting read write page test on recovery flash controller");
    let test_cb_recovery = unsafe { static_init_test!() };
    test_single_flash_ctrl_read_write_page(&peripherals.secondary_flash_ctrl, test_cb_recovery);

    Some(0)
}
