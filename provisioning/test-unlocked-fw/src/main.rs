// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod riscv {
    use caliptra_mcu_provisioning_common::init_provisioning;
    use caliptra_mcu_provisioning_fuses::FUSE_VALUES;

    use caliptra_mcu_registers_generated::fuses::{self, FuseEntryInfo};
    use caliptra_mcu_registers_generated::otp_ctrl;
    use caliptra_mcu_romtime::otp::Otp;
    use caliptra_mcu_romtime::println;
    use caliptra_mcu_romtime::StaticRef;
    use core::arch::global_asm;
    use core::panic::PanicInfo;
    use tock_registers::interfaces::Readable;

    global_asm!(include_str!("start.S"));

    const TEST_UNLOCKED_FUSES: &[&str] = &[
        "CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_1",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_2",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_3",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_4",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_5",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_6",
        "CPTRA_SS_TEST_UNLOCK_TOKEN_7",
        "CPTRA_SS_TEST_EXIT_TO_MANUF_TOKEN",
        "CPTRA_SS_MANUF_TO_PROD_TOKEN",
        "CPTRA_SS_PROD_TO_PROD_END_TOKEN",
        "CPTRA_SS_RMA_TOKEN",
    ];

    #[no_mangle]
    pub extern "C" fn main() {
        let otp = caliptra_mcu_provisioning_common::init_provisioning(
            "Caliptra SS Provisioning [TEST_UNLOCKED]",
        );

        caliptra_mcu_provisioning_common::burn_and_verify_fuses(&otp, TEST_UNLOCKED_FUSES);

        caliptra_mcu_bare_metal_io::println("Finalizing SW_TEST_UNLOCK partition...");
        if let Err(e) = otp.finalize_digest(fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET) {
            caliptra_mcu_bare_metal_io::println("Error finalizing SW_TEST_UNLOCK digest");
            caliptra_mcu_bare_metal_io::exit(u32::from(e));
        }

        caliptra_mcu_bare_metal_io::println("Finalizing SECRET_LC_TRANSITION partition...");
        if let Err(e) = otp.finalize_digest(fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET) {
            caliptra_mcu_bare_metal_io::println("Error finalizing SECRET_LC_TRANSITION digest");
            caliptra_mcu_bare_metal_io::exit(u32::from(e));
        }

        caliptra_mcu_bare_metal_io::println("TEST_UNLOCKED provisioning completed successfully!");
        caliptra_mcu_bare_metal_io::exit(0);
    }

    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    println!("nop");
}
