// Test flash controller driver read, write, erage page

use core::cell::Cell;
use kernel::{debug, debug_flush_queue};
use kernel::hil;
use kernel::hil::flash::HasClient;
use kernel::static_init;
use kernel::utilities::cells::TakeCell;


fn success() -> ! {
    debug_flush_queue!();
    crate::io::exit_emulator(0);
}

#[allow(dead_code)]
fn fail() -> ! {
    debug_flush_queue!();
    crate::io::exit_emulator(1);
}

pub(crate) fn test_flash_ctrl_init () -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    chip.peripherals.flash_ctrl.init();
    Some(0)
}
