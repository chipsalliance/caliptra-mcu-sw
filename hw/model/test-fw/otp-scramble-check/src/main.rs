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

use mcu_rom_common::{fatal_error, RomEnv};
use registers_generated::fuses;
use tock_registers::interfaces::Readable;

const GO_BIT: u32 = 1 << 0;

fn run() -> ! {
    let env = RomEnv::new();
    let otp = &env.otp;

    // Wait for go-bit (FPGA OTP clearing preamble).
    while env.mci.registers.mci_reg_generic_input_wires[0].get() & GO_BIT == 0 {}

    let partition = fuses::VENDOR_SECRET_PROD_PARTITION;
    let dword_addr = partition.byte_offset / 8;

    romtime::println!(
        "[otp-scramble-check] Reading dword at byte offset 0x{:03x} via DAI",
        partition.byte_offset
    );

    match otp.read_dword(dword_addr) {
        Ok(val) => {
            let lo = val as u32;
            let hi = (val >> 32) as u32;
            romtime::println!("[otp-scramble-check] DESCRAMBLED_LO={:08X}", lo);
            romtime::println!("[otp-scramble-check] DESCRAMBLED_HI={:08X}", hi);
        }
        Err(_) => {
            romtime::println!("[otp-scramble-check] DAI read failed");
            fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR);
        }
    }

    romtime::println!("[otp-scramble-check] PASS");
    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
