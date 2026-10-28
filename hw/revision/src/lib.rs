// Licensed under the Apache-2.0 license

use std::{env, fmt, path::Path};

pub const ENV: &str = "CALIPTRA_HW_REV";
pub const DEFAULT: HardwareRevision = HardwareRevision::V2_1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareRevision {
    V2_1,
    Latest,
}

impl HardwareRevision {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "2.1" => Ok(Self::V2_1),
            "latest" => Ok(Self::Latest),
            _ => Err(format!(
                "Unsupported {ENV}={value:?}; expected 2.1 or latest (2.2 is not yet a supported selector)"
            )),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        match env::var(ENV) {
            Ok(value) => Self::parse(&value),
            Err(env::VarError::NotPresent) => Ok(DEFAULT),
            Err(error) => Err(format!("Invalid {ENV}: {error}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2_1 => "2.1",
            Self::Latest => "latest",
        }
    }

    pub const fn directory(self) -> &'static str {
        match self {
            Self::V2_1 => "rev_2_1",
            Self::Latest => "latest",
        }
    }

    pub const fn inputs_path(self) -> &'static str {
        match self {
            Self::V2_1 => "hw/rev-2_1",
            Self::Latest => "hw/latest",
        }
    }

    pub const fn hardware_path(self) -> &'static str {
        match self {
            Self::V2_1 => "hw/rev-2_1/caliptra-ss",
            Self::Latest => "hw/latest/caliptra-ss",
        }
    }

    pub const fn fpga_path(self) -> &'static str {
        match self {
            Self::V2_1 => "hw/rev-2_1/fpga",
            Self::Latest => "hw/latest/fpga",
        }
    }

    // This is the existing emulator/core behavior contract, not the MCU register
    // revision. Full 2.2 behavior remains gated on core alignment and new models.
    pub const fn emulator_version(self) -> &'static str {
        "2.1.0"
    }

    pub fn validate_emulator_version(self, value: &str) -> Result<(), String> {
        if value == self.emulator_version() {
            Ok(())
        } else {
            Err(format!(
                "emulator revision {value} does not match {ENV}={self} (expected {})",
                self.emulator_version()
            ))
        }
    }

    pub fn cache_name(self, name: &str) -> String {
        format!("{}-{name}", self.directory())
    }

    pub fn emit_build_configuration(self) {
        println!("cargo:rerun-if-env-changed={ENV}");
        println!("cargo:rustc-check-cfg=cfg(hw_rev, values(\"2.1\", \"latest\"))");
        println!("cargo:rustc-cfg=hw_rev=\"{self}\"");
        println!("cargo:rustc-env=CALIPTRA_MCU_HW_REV={self}");
    }

    pub fn otp_mmap(self, root: &Path) -> std::path::PathBuf {
        root.join(self.hardware_path())
            .join("src/fuse_ctrl/data/otp_ctrl_mmap.hjson")
    }

    pub fn fuses_hjson(self, root: &Path) -> std::path::PathBuf {
        root.join(self.inputs_path()).join("fuses.hjson")
    }
}

impl fmt::Display for HardwareRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_selectors_and_default() {
        assert_eq!(DEFAULT, HardwareRevision::V2_1);
        assert_eq!(HardwareRevision::parse("2.1"), Ok(DEFAULT));
        assert_eq!(
            HardwareRevision::parse("latest"),
            Ok(HardwareRevision::Latest)
        );
        for value in ["", "2.0", "2.2", "2.1.0", "../latest"] {
            assert!(HardwareRevision::parse(value).is_err());
        }
    }

    #[test]
    fn revision_paths_and_caches_are_independent() {
        let stable = HardwareRevision::V2_1;
        let latest = HardwareRevision::Latest;
        assert_ne!(stable.hardware_path(), latest.hardware_path());
        assert_ne!(stable.fpga_path(), latest.fpga_path());
        assert_ne!(stable.directory(), latest.directory());
        assert_ne!(stable.cache_name("rom.bin"), latest.cache_name("rom.bin"));
        assert!(stable.validate_emulator_version("2.1.0").is_ok());
        assert!(latest.validate_emulator_version("2.2.0").is_err());
    }

    #[test]
    fn hardware_inputs_are_selected_together() {
        for (revision, inputs) in [
            (HardwareRevision::V2_1, "hw/rev-2_1"),
            (HardwareRevision::Latest, "hw/latest"),
        ] {
            let inputs = Path::new(inputs);
            assert_eq!(Path::new(revision.inputs_path()), inputs);
            assert_eq!(
                Path::new(revision.hardware_path()),
                inputs.join("caliptra-ss")
            );
            assert_eq!(
                revision.fuses_hjson(Path::new(".")),
                Path::new(".").join(inputs).join("fuses.hjson")
            );
            assert_eq!(
                revision.otp_mmap(Path::new(".")),
                Path::new(".")
                    .join(inputs)
                    .join("caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson"),
            );
        }
    }

    #[test]
    fn fpga_inputs_match_hardware_revision() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for (revision, directory) in [
            (HardwareRevision::V2_1, "rev-2_1"),
            (HardwareRevision::Latest, "latest"),
        ] {
            let fpga = root.join(revision.fpga_path());
            assert_eq!(fpga, root.join("hw").join(directory).join("fpga"));
            for input in [
                "fpga_configuration.tcl",
                "bitstream_manifests/subsystem.toml",
                "kernel-modules/Makefile",
                "launch_openocd.sh",
                "src/caliptra_fpga_realtime_regs.rdl",
            ] {
                assert!(fpga.join(input).is_file(), "{revision}: {input}");
            }
            let configuration =
                std::fs::read_to_string(fpga.join("fpga_configuration.tcl")).unwrap();
            assert!(configuration.contains("set ssrtlDir $fpgaDir/../caliptra-ss"));
        }
    }
}
