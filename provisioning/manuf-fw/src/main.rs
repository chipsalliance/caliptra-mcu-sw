// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod riscv {
    use caliptra_mcu_provisioning_common::init_provisioning;
    use caliptra_mcu_provisioning_fuses::FUSE_VALUES;

    use caliptra_mcu_registers_generated::fuses;
    use caliptra_mcu_registers_generated::otp_ctrl;
    use caliptra_mcu_romtime::otp::Otp;
    use caliptra_mcu_romtime::StaticRef;
    use core::arch::global_asm;
    use core::panic::PanicInfo;
    use tock_registers::interfaces::{Readable, Writeable};

    use caliptra_mcu_otp_digest::{OTP_DIGEST_CONST, OTP_DIGEST_IV};

    global_asm!(include_str!("start.S"));

    const MANUF_FUSES: &[&str] = &[
        "CPTRA_CORE_ANTI_ROLLBACK_DISABLE",
        "CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR",
        "SOC_SPECIFIC_IDEVID_CERTIFICATE",
        "CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER",
        "CPTRA_CORE_SOC_STEPPING_ID",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6",
        "CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7",
        "CPTRA_CORE_VENDOR_PK_HASH_0",
        "CPTRA_CORE_PQC_KEY_TYPE_0",
        "CPTRA_SS_OWNER_PK_HASH",
        "CPTRA_SS_OWNER_PQC_KEY_TYPE",
        "CPTRA_SS_OWNER_PK_HASH_VALID",
        "CPTRA_CORE_VENDOR_PK_HASH_1",
        "CPTRA_CORE_VENDOR_PK_HASH_2",
        "CPTRA_CORE_VENDOR_PK_HASH_3",
        "CPTRA_CORE_PQC_KEY_TYPE_1",
        "CPTRA_CORE_PQC_KEY_TYPE_2",
        "CPTRA_CORE_PQC_KEY_TYPE_3",
        "CPTRA_CORE_VENDOR_PK_HASH_VALID",
    ];

    #[no_mangle]
    pub extern "C" fn main() {
        let otp =
            caliptra_mcu_provisioning_common::init_provisioning("Caliptra SS Provisioning [MANUF]");

        caliptra_mcu_provisioning_common::burn_and_verify_fuses(&otp, MANUF_FUSES);

        caliptra_mcu_bare_metal_io::println(
            "Computing and writing SW_MANUF partition SW digest...",
        );
        if let Err(e) = otp.write_sw_digest_and_lock(
            &fuses::SW_MANUF_PARTITION,
            OTP_DIGEST_IV,
            OTP_DIGEST_CONST,
        ) {
            caliptra_mcu_bare_metal_io::println("Error writing SW_MANUF SW digest");
            caliptra_mcu_bare_metal_io::exit(u32::from(e));
        }

        caliptra_mcu_bare_metal_io::println(
            "Computing and writing VENDOR_HASHES_MANUF partition SW digest...",
        );
        if let Err(e) = otp.write_sw_digest_and_lock(
            &fuses::VENDOR_HASHES_MANUF_PARTITION,
            OTP_DIGEST_IV,
            OTP_DIGEST_CONST,
        ) {
            caliptra_mcu_bare_metal_io::println("Error writing VENDOR_HASHES_MANUF SW digest");
            caliptra_mcu_bare_metal_io::exit(u32::from(e));
        }

        caliptra_mcu_bare_metal_io::println("MANUF provisioning completed successfully!");
        caliptra_mcu_bare_metal_io::exit(0);
    }

    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {}
