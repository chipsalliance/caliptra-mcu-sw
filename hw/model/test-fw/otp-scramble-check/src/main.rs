// Licensed under the Apache-2.0 license

//! Test ROM that reads a secret OTP partition via DAI and prints the
//! descrambled value to UART.
//!
//! The host pre-populates the raw OTP SRAM (backdoor) with known bytes
//! at the vendor_secret_prod_partition offset before boot. The OTP
//! controller descrambles on DAI read. The host then compares the
//! printed value against its own Rust PRESENT computation.

#![no_main]
#![no_std]

use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_rom_common::{fatal_error, RomEnv};
use tock_registers::interfaces::{Readable, Writeable};

const GO_BIT: u32 = 1 << 0;

fn run() -> ! {
    let env = RomEnv::new();

    // Configure iTRNG in bypass mode via ss_strap_generic[2] to provide mock
    // entropy and prevent the OTP controller from hanging during key
    // calculation on the emulator. We perform a raw write to avoid accessing
    // the TRNG configuration registers, which may not be implemented in the
    // emulator's RTL and could hang the bus.
    #[cfg(not(feature = "fpga_realtime"))]
    unsafe {
        let soc = &*(caliptra_mcu_rom_common::MCU_MEMORY_MAP.soc_offset
            as *const caliptra_mcu_registers_generated::soc::regs::Soc);
        soc.ss_strap_generic[2].set((1 << 31) | 100);
    }

    let otp = &env.otp;

    // Release Caliptra reset so host can access its registers without hanging.
    env.mci.caliptra_boot_go();

    // Wait for go-bit (FPGA OTP clearing preamble).
    while env.mci.registers.mci_reg_generic_input_wires[0].get() & GO_BIT == 0 {}

    let partition = fuses::VENDOR_SECRET_PROD_PARTITION;
    let dword_addr = partition.byte_offset / 8;

    caliptra_mcu_romtime::println!(
        "[otp-scramble-check] Reading dword at byte offset 0x{:03x} via DAI",
        partition.byte_offset
    );

    match otp.read_dword(dword_addr) {
        Ok(val) => {
            let lo = val as u32;
            let hi = (val >> 32) as u32;
            caliptra_mcu_romtime::println!("[otp-scramble-check] DESCRAMBLED_LO={:08X}", lo);
            caliptra_mcu_romtime::println!("[otp-scramble-check] DESCRAMBLED_HI={:08X}", hi);
        }
        Err(_) => {
            caliptra_mcu_romtime::println!("[otp-scramble-check] DAI read failed");
            fatal_error(caliptra_mcu_error::McuError::ROM_OTP_READ_ERROR);
        }
    }

    caliptra_mcu_romtime::println!("[otp-scramble-check] PASS");
    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
pub extern "C" fn main() {
    caliptra_mcu_test_harness::set_printer();
    run();
}
