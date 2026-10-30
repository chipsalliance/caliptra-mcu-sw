// Licensed under the Apache-2.0 license

use std::{env, fmt, path::Path};

pub const ENV: &str = "CALIPTRA_HW_REV";
pub const DEFAULT: HardwareRevision = HardwareRevision::Latest;

/// Functionality provided by a selected hardware revision and its pinned Core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    UsbSupport,
    RecoveryInterfaceSelect,
    OwnerPkHashMailbox,
    OwnerPkHashRegisters,
    MboxTargetDone,
    MboxStatusCompletion,
}

impl Capability {
    pub const ALL: &'static [Self] = &[
        Self::UsbSupport,
        Self::RecoveryInterfaceSelect,
        Self::OwnerPkHashMailbox,
        Self::OwnerPkHashRegisters,
        Self::MboxTargetDone,
        Self::MboxStatusCompletion,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsbSupport => "usb-support",
            Self::RecoveryInterfaceSelect => "recovery-interface-select",
            Self::OwnerPkHashMailbox => "owner-pk-hash-mailbox",
            Self::OwnerPkHashRegisters => "owner-pk-hash-registers",
            Self::MboxTargetDone => "mbox-target-done",
            Self::MboxStatusCompletion => "mbox-status-completion",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareRevision {
    V2_1,
    Latest,
}

impl HardwareRevision {
    pub const fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::V2_1 => &[Capability::OwnerPkHashMailbox, Capability::MboxTargetDone],
            Self::Latest => &[
                Capability::UsbSupport,
                Capability::RecoveryInterfaceSelect,
                Capability::OwnerPkHashRegisters,
                Capability::MboxStatusCompletion,
            ],
        }
    }

    pub fn supports(self, capability: Capability) -> bool {
        self.capabilities().contains(&capability)
    }

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
        print!("{}", self.build_configuration());
    }

    fn build_configuration(self) -> String {
        let names = Capability::ALL
            .iter()
            .map(|capability| format!("\"{}\"", capability.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let mut configuration = format!(
            "cargo:rerun-if-env-changed={ENV}\n\
             cargo:rustc-check-cfg=cfg(hw_rev, values(\"2.1\", \"latest\"))\n\
             cargo:rustc-check-cfg=cfg(hw_capability, values({names}))\n\
             cargo:rustc-cfg=hw_rev=\"{self}\"\n\
             cargo:rustc-env=CALIPTRA_MCU_HW_REV={self}\n"
        );
        for capability in self.capabilities() {
            configuration.push_str(&format!(
                "cargo:rustc-cfg=hw_capability=\"{}\"\n",
                capability.as_str()
            ));
        }
        configuration
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
    fn capability_matrix_matches_selected_hardware_and_core_contract() {
        use Capability::*;

        assert_eq!(
            HardwareRevision::V2_1.capabilities(),
            &[OwnerPkHashMailbox, MboxTargetDone]
        );
        assert_eq!(
            HardwareRevision::Latest.capabilities(),
            &[
                UsbSupport,
                RecoveryInterfaceSelect,
                OwnerPkHashRegisters,
                MboxStatusCompletion,
            ]
        );
        for revision in [HardwareRevision::V2_1, HardwareRevision::Latest] {
            assert_ne!(
                revision.supports(OwnerPkHashMailbox),
                revision.supports(OwnerPkHashRegisters)
            );
            assert_ne!(
                revision.supports(MboxTargetDone),
                revision.supports(MboxStatusCompletion)
            );
        }
    }

    #[test]
    fn build_configuration_registers_all_capabilities_and_enables_only_selected_ones() {
        let names: std::collections::HashSet<_> = Capability::ALL
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        assert_eq!(names.len(), Capability::ALL.len());

        for revision in [HardwareRevision::V2_1, HardwareRevision::Latest] {
            let configuration = revision.build_configuration();
            let check_cfg = configuration
                .lines()
                .find(|line| line.starts_with("cargo:rustc-check-cfg=cfg(hw_capability,"))
                .unwrap();
            for capability in Capability::ALL {
                let name = capability.as_str();
                assert!(check_cfg.contains(&format!("\"{name}\"")));
                assert_eq!(
                    configuration
                        .lines()
                        .filter(|line| *line == format!("cargo:rustc-cfg=hw_capability=\"{name}\""))
                        .count(),
                    usize::from(revision.supports(*capability)),
                    "{revision}: {name}"
                );
            }
            assert!(configuration.contains(&format!("cargo:rustc-cfg=hw_rev=\"{revision}\"\n")));
            assert!(configuration
                .contains(&format!("cargo:rustc-env=CALIPTRA_MCU_HW_REV={revision}\n")));
            assert!(configuration.contains(&format!("cargo:rerun-if-env-changed={ENV}\n")));
        }
    }

    #[test]
    fn supported_selectors_and_default() {
        assert_eq!(DEFAULT, HardwareRevision::Latest);
        assert_eq!(HardwareRevision::parse("2.1"), Ok(HardwareRevision::V2_1));
        assert_eq!(HardwareRevision::parse("latest"), Ok(DEFAULT));
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
