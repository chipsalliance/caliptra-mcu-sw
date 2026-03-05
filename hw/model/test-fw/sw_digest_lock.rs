// Licensed under the Apache-2.0 license

//! Test ROM for `Otp::write_sw_digest_and_lock`.
//!
//! Boot 1: partition digest is zero - populate vendor_test_partition and
//!         write the SW digest. Print "DONE" and loop.
//!
//! Boot 2: partition digest is non-zero - re-compute the digest and verify
//!         it matches the stored value. Print "PASS" or fatal_error.

#![no_main]
#![no_std]

use mcu_rom_common::{fatal_error, RomEnv};
use registers_generated::fuses;
use romtime::otp::Otp;
use tock_registers::interfaces::Readable;

#[allow(unused)]
use mcu_test_harness;

const DIGEST_IV: u64 = 0x90C7_F21F_6224_F027;
const DIGEST_CONST: u128 = 0xF98C_48B1_F937_7284_4A22_D4B7_8FE0_266F;

fn populate_vendor_test_partition(otp: &Otp) {
    let partition = fuses::VENDOR_TEST_PARTITION;
    let data_len = partition.byte_size - 8;
    let base_word = partition.byte_offset / 4;
    let num_words = data_len / 4;

    for i in 0..num_words {
        let val = (i as u32).wrapping_mul(0x0101_0101);
        if let Err(_e) = otp.write_word(base_word + i, val) {
            romtime::println!("[sw-digest-lock] Failed to write OTP word {}", i);
            fatal_error(mcu_error::McuError::ROM_OTP_WRITE_WORD_ERROR);
        }
    }
}

fn write_phase(env: &RomEnv) -> ! {
    let otp = &env.otp;
    let partition = fuses::VENDOR_TEST_PARTITION;

    romtime::println!("[sw-digest-lock] Write phase: populating partition and writing digest");
    populate_vendor_test_partition(otp);

    match otp.write_sw_digest_and_lock(partition, DIGEST_IV, DIGEST_CONST) {
        Ok(digest) => {
            romtime::println!("[sw-digest-lock] Digest written: {:#018x}", digest);
        }
        Err(_e) => {
            romtime::println!("[sw-digest-lock] write_sw_digest_and_lock failed");
            fatal_error(mcu_error::McuError::ROM_OTP_DIGEST_VERIFY_ERROR);
        }
    }

    romtime::println!("[sw-digest-lock] DONE");
    loop {}
}

fn verify_phase(env: &RomEnv) -> ! {
    let otp = &env.otp;
    let partition = fuses::VENDOR_TEST_PARTITION;

    romtime::println!("[sw-digest-lock] Verify phase: checking digest");

    let computed = match otp.compute_sw_digest(partition, DIGEST_IV, DIGEST_CONST) {
        Ok(d) => d,
        Err(_e) => {
            romtime::println!("[sw-digest-lock] compute_sw_digest failed");
            fatal_error(mcu_error::McuError::ROM_OTP_DIGEST_VERIFY_ERROR);
        }
    };

    let digest_offset = match partition.digest_offset {
        Some(off) => off,
        None => fatal_error(mcu_error::McuError::ROM_OTP_INVALID_DATA_ERROR),
    };
    let stored = match otp.read_dword(digest_offset / 8) {
        Ok(v) => v,
        Err(_e) => fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR),
    };

    romtime::println!(
        "[sw-digest-lock] Computed: {:#018x}, Stored: {:#018x}",
        computed,
        stored
    );

    if stored != computed {
        romtime::println!("[sw-digest-lock] MISMATCH!");
        fatal_error(mcu_error::McuError::ROM_OTP_DIGEST_VERIFY_ERROR);
    }

    romtime::println!("[sw-digest-lock] PASS");
    loop {}
}

/// Go-bit in generic_input_wires[0] gates execution on FPGA to prevent
/// racing with the OTP clearing preamble.
const GO_BIT: u32 = 1 << 0;

fn run() -> ! {
    let env = RomEnv::new();

    // Wait for go-bit (FPGA OTP clearing preamble).
    while env.mci.registers.mci_reg_generic_input_wires[0].get() & GO_BIT == 0 {}

    // Check if the digest is already written to decide which phase.
    let partition = fuses::VENDOR_TEST_PARTITION;
    let digest_offset = match partition.digest_offset {
        Some(off) => off,
        None => fatal_error(mcu_error::McuError::ROM_OTP_INVALID_DATA_ERROR),
    };
    let stored = match env.otp.read_dword(digest_offset / 8) {
        Ok(v) => v,
        Err(_e) => fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR),
    };

    if stored == 0 {
        write_phase(&env)
    } else {
        verify_phase(&env)
    }
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
