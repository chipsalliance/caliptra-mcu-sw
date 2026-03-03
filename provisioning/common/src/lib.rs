// Licensed under the Apache-2.0 license

#![no_std]

#[cfg(target_arch = "riscv32")]
mod riscv {
    use caliptra_mcu_registers_generated::otp_ctrl;
    use caliptra_mcu_romtime::{otp::Otp, StaticRef};

    struct BareMetalWriter;

    impl core::fmt::Write for BareMetalWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            caliptra_mcu_bare_metal_io::print(s);
            Ok(())
        }
    }

    static mut WRITER: BareMetalWriter = BareMetalWriter;

    pub fn init_provisioning(welcome_msg: &str) -> Otp {
        caliptra_mcu_bare_metal_io::println(welcome_msg);

        unsafe {
            #[allow(static_mut_refs)]
            caliptra_mcu_romtime::set_printer(&mut WRITER);
        }

        let otp_regs: StaticRef<otp_ctrl::regs::OtpCtrl> = unsafe {
            StaticRef::new(caliptra_mcu_bare_metal_io::OTP_OFFSET as *const otp_ctrl::regs::OtpCtrl)
        };
        Otp::new(otp_regs)
    }

    pub fn burn_and_verify_fuses(otp: &Otp, fuses: &[&str]) {
        use caliptra_mcu_provisioning_fuses::FUSE_VALUES;

        // Loop over FUSE_VALUES and program targeted fuses
        for &(info, value) in FUSE_VALUES {
            if !fuses.contains(&info.name) || value.iter().all(|&b| b == 0) {
                continue;
            }

            caliptra_mcu_bare_metal_io::print("Burning ");
            caliptra_mcu_bare_metal_io::println(info.name);

            if let Err(e) = otp.write_entry_raw(info, value) {
                caliptra_mcu_bare_metal_io::println("Error burning fuse");
                caliptra_mcu_bare_metal_io::exit(u32::from(e));
            }
        }

        // Loop over FUSE_VALUES and verify targeted fuses before locking
        let mut read_buf = [0u8; 128];
        for &(info, value) in FUSE_VALUES {
            if !fuses.contains(&info.name) {
                continue;
            }

            caliptra_mcu_bare_metal_io::print("Verifying ");
            caliptra_mcu_bare_metal_io::println(info.name);

            let size = info.byte_size;
            read_buf[..size].fill(0);
            if let Err(e) = otp.read_entry_raw(info, &mut read_buf[..size]) {
                caliptra_mcu_bare_metal_io::println("Error reading back fuse");
                caliptra_mcu_bare_metal_io::exit(u32::from(e));
            }

            if read_buf[..size] != value[..size] {
                caliptra_mcu_bare_metal_io::println("Fuse verification failed: mismatch!");
                caliptra_mcu_bare_metal_io::exit(1);
            }
        }
    }
}

#[cfg(target_arch = "riscv32")]
pub use riscv::*;
