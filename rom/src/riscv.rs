/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

pub extern "C" fn rom_entry() -> ! {
    crate::io::write(b"Hello from ROM\n");
    exit_rom();
}

fn exit_rom() -> ! {
    unsafe {
        core::arch::asm! {
                "// Clear the stack
            la a0, STACK_START         // dest
            la a1, STACK_SIZE        // len

            li a2, 0
            add a1, a1, a0
        1:
            sw a2, 0(a0)
            sw a2, 4(a0)
            sw a2, 8(a0)
            sw a2, 12(a0)
            sw a2, 16(a0)
            sw a2, 20(a0)
            sw a2, 24(a0)
            sw a2, 28(a0)
            addi a0, a0, 32
            bltu a0, a1, 1b



            // Clear all registers
            li x1,  0; li x2,  0; li x3,  0; li x4,  0;
            li x5,  0; li x6,  0; li x7,  0; li x8,  0;
            li x9,  0; li x10, 0; li x11, 0; li x12, 0;
            li x13, 0; li x14, 0; li x15, 0; li x16, 0;
            li x17, 0; li x18, 0; li x19, 0; li x20, 0;
            li x21, 0; li x22, 0; li x23, 0; li x24, 0;
            li x25, 0; li x26, 0; li x27, 0; li x28, 0;
            li x29, 0; li x30, 0; li x31, 0;

            // jump to runtime
            li a3, 0x40000080
            jr a3",
                options(noreturn),
        }
    }
}
