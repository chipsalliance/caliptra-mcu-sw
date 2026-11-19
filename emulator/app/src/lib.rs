/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Library interface for the Caliptra MCU Emulator.

--*/

pub mod dis;
pub mod dis_test;
pub mod doe_mbox_fsm;
pub mod elf;
pub mod emulator;
pub mod gdb;
pub mod tests;

pub use emulator::{Emulator, EmulatorArgs, ExternalReadCallback, ExternalWriteCallback};

#[cfg(test)]
mod hardware_revision_tests {
    use super::{Emulator, EmulatorArgs};
    use clap::Parser;

    fn args() -> EmulatorArgs {
        EmulatorArgs::parse_from([
            "emulator",
            "--rom",
            "unused",
            "--firmware",
            "unused",
            "--caliptra-rom",
            "unused",
            "--caliptra-firmware",
            "unused",
            "--soc-manifest",
            "unused",
        ])
    }

    #[test]
    fn hardware_revision_default_matches_compiled_contract() {
        let revision = caliptra_mcu_hw_revision::HardwareRevision::parse(
            caliptra_mcu_emulator_registers_generated::HARDWARE_REVISION,
        )
        .unwrap();
        assert!(revision
            .validate_emulator_version(&args().hw_revision.to_string())
            .is_ok());
    }

    #[test]
    fn hardware_revision_mismatch_is_rejected_before_io() {
        for value in ["2.0.0", "2.2.0"] {
            let mut args = args();
            args.hw_revision = value.parse().unwrap();
            let error = match Emulator::from_args(args, false) {
                Err(error) => error,
                Ok(_) => panic!("incompatible emulator revision was accepted"),
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("does not match CALIPTRA_HW_REV"));
        }
    }
}
