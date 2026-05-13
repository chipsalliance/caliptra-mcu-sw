// Licensed under the Apache-2.0 license

//! Test ROM that verifies OTP blank-check enforcement.
//!
//! 1. Write 0x0000_000F to the first data word of vendor_test_partition.
//! 2. Read it back to confirm.
//! 3. Attempt to write 0x0000_0001 to the same word (clears bits 1-3).
//! 4. Verify that the write fails (returns Err) due to blank-check.
//! 5. Read back to confirm the original value is unchanged.
//!
//! Prints "PASS" on success, or a diagnostic message before fatal_error.

#![no_main]
#![no_std]

use mcu_rom_common::{fatal_error, RomEnv};
use registers_generated::fuses;

fn run() -> ! {
    let env = RomEnv::new();
    let otp = &env.otp;

    let partition = fuses::VENDOR_TEST_PARTITION;
    let base_word = partition.byte_offset / 4;

    // Write 0x0F to a blank word.
    romtime::println!("[otp-blank-check] Writing 0x0000000F to word {}", base_word);
    match otp.write_word(base_word, 0x0000_000F) {
        Ok(_) => {}
        Err(_) => {
            romtime::println!("[otp-blank-check] First write unexpectedly failed");
            fatal_error(mcu_error::McuError::ROM_OTP_WRITE_WORD_ERROR);
        }
    }

    // Read back and verify.
    match otp.read_word(base_word) {
        Ok(val) => {
            if val != 0x0000_000F {
                romtime::println!("[otp-blank-check] Read back wrong value after first write");
                fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR);
            }
        }
        Err(_) => {
            romtime::println!("[otp-blank-check] Read after first write failed");
            fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR);
        }
    }
    romtime::println!("[otp-blank-check] First write verified OK");

    // Attempt a write that would clear bits — must fail with blank-check error.
    romtime::println!("[otp-blank-check] Attempting write of 0x00000001 (should fail)");
    match otp.write_word(base_word, 0x0000_0001) {
        Ok(_) => {
            romtime::println!("[otp-blank-check] Second write succeeded but should have failed");
            fatal_error(mcu_error::McuError::ROM_OTP_WRITE_WORD_ERROR);
        }
        Err(_) => {
            romtime::println!("[otp-blank-check] Second write correctly failed");
        }
    }

    // Confirm original value is preserved after the failed write.
    match otp.read_word(base_word) {
        Ok(val) => {
            if val != 0x0000_000F {
                romtime::println!(
                    "[otp-blank-check] Original value not preserved, got {:#010x}",
                    val
                );
                fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR);
            }
        }
        Err(_) => {
            romtime::println!("[otp-blank-check] Final readback failed");
            fatal_error(mcu_error::McuError::ROM_OTP_READ_ERROR);
        }
    }

    romtime::println!("[otp-blank-check] PASS");
    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
