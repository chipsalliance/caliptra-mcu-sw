/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

use crate::io::{print_to_console, EXITER, FATAL_ERROR_HANDLER, FPGA_WRITER};
use core::fmt::Write;

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

use mcu_config::{McuMemoryMap, McuStraps};

// re-export these so the common ROM and runtime can use them
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_fpga::FPGA_MEMORY_MAP;

#[no_mangle]
#[used]
pub static MCU_STRAPS: McuStraps = mcu_config_fpga::FPGA_MCU_STRAPS;

pub extern "C" fn rom_entry() -> ! {
    print_to_console("FPGA MCU ROM\n");
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut FPGA_WRITER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        mcu_rom_common::set_fatal_error_handler(&mut FATAL_ERROR_HANDLER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_exiter(&mut EXITER);
    }

    romtime::println!("[mcu-rom] Starting FPGA MCU ROM");

    mcu_rom_common::rom_start(None);

    let addr = MCU_MEMORY_MAP.sram_offset;
    romtime::println!("[mcu-rom] Jumping to firmware at {:08x}", addr);
    exit_rom(addr);
}

fn exit_rom(addr: u32) -> ! {
    unsafe {
        core::arch::asm! {
                "// Clear the stack
            la a0, STACK_ORIGIN      // dest
            la a1, STACK_SIZE        // len
            add a1, a1, a0
        1:
            sw zero, 0(a0)
            addi a0, a0, 4
            bltu a0, a1, 1b


            // Clear all registers
            li x1,  0; li x2,  0; li x3,  0; li x4,  0;
            li x5,  0; li x6,  0; li x7,  0; li x8,  0;
            li x9,  0; li x10, 0; li x11, 0; li x12, 0;
            li x14, 0; li x15, 0; li x16, 0;
            li x17, 0; li x18, 0; li x19, 0; li x20, 0;
            li x21, 0; li x22, 0; li x23, 0; li x24, 0;
            li x25, 0; li x26, 0; li x27, 0; li x28, 0;
            li x29, 0; li x30, 0; li x31, 0;

            // jump to runtime
            jr a3",
                in("a3") addr,
                options(noreturn),
        }
    }
}
