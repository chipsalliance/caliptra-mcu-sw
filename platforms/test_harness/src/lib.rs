// Licensed under the Apache-2.0 license

#![no_std]

pub use platform::*;

use core::fmt::Write;
use mcu_config::{McuMemoryMap, McuStraps};

#[cfg(all(target_arch = "riscv32", feature = "fpga_realtime"))]
core::arch::global_asm!(include_str!("fpga-start.s"));

#[cfg(all(target_arch = "riscv32", not(feature = "fpga_realtime")))]
core::arch::global_asm!(include_str!("emulator-start.s"));

// re-export these so the common ROM can use it
#[cfg(feature = "fpga_realtime")]
mod platform {
    use super::*;
    #[no_mangle]
    #[used]
    pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_fpga::FPGA_MEMORY_MAP;
    #[no_mangle]
    #[used]
    pub static MCU_STRAPS: McuStraps = mcu_config_fpga::FPGA_MCU_STRAPS;

    pub(crate) struct FpgaWriter {}
    pub(crate) static mut WRITER: FpgaWriter = FpgaWriter {};

    const FPGA_UART_OUTPUT: *mut u32 = 0xa401_1014 as *mut u32;

    impl Write for FpgaWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            print_to_console(s);
            Ok(())
        }
    }

    pub(crate) fn print_to_console(buf: &str) {
        for b in buf.bytes() {
            // Print to this address for FPGA output
            unsafe {
                core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
            }
        }
    }
}
#[cfg(not(feature = "fpga_realtime"))]
mod platform {
    use super::*;
    #[no_mangle]
    #[used]
    pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_emulator::EMULATOR_MEMORY_MAP;
    #[no_mangle]
    #[used]
    pub static MCU_STRAPS: McuStraps = mcu_config_emulator::EMULATOR_MCU_STRAPS;

    pub(crate) struct EmulatorWriter {}
    pub(crate) static mut WRITER: EmulatorWriter = EmulatorWriter {};

    impl Write for EmulatorWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            print_to_console(s);
            Ok(())
        }
    }

    pub(crate) fn print_to_console(buf: &str) {
        for b in buf.bytes() {
            // Print to this address for emulator output
            unsafe {
                core::ptr::write_volatile(0x1000_1041 as *mut u8, b);
            }
        }
    }
}

/// Must be called prior to using `romtime::println` or similar functions
pub fn set_printer() {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut WRITER);
    }
}
