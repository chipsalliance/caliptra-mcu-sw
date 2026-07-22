// Licensed under the Apache-2.0 license

use caliptra_builder::FwId;

pub mod hw_model_tests {
    use super::*;

    pub const MAILBOX_RESPONDER: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-mailbox-responder",
        bin_name: "caliptra-mcu-test-fw-mailbox-responder",
        features: &["emu"],
    };

    pub const HITLESS_UPDATE_FLOW: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-hitless-update-flow",
        bin_name: "caliptra-mcu-test-fw-hitless-update-flow",
        features: &["emu"],
    };

    pub const AXI_BYPASS: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-axi-bypass",
        bin_name: "caliptra-mcu-test-fw-axi-bypass",
        features: &["emu"],
    };

    pub const EXCEPTION_HANDLER: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-exception-handler",
        bin_name: "caliptra-mcu-test-fw-exception-handler",
        features: &["emu"],
    };

    pub const USB_RESPONDER: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-usb-responder",
        bin_name: "caliptra-mcu-test-fw-usb-responder",
        features: &["emu"],
    };

    pub const USB_OCP_RECOVERY: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-usb-ocp-recovery",
        bin_name: "caliptra-mcu-test-fw-usb-ocp-recovery",
        features: &["emu"],
    };

    pub const SW_DIGEST_LOCK: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-sw-digest-lock",
        bin_name: "caliptra-mcu-test-fw-sw-digest-lock",
        features: &["emu"],
    };

    pub const OTP_BLANK_CHECK: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-otp-blank-check",
        bin_name: "caliptra-mcu-test-fw-otp-blank-check",
        features: &["emu"],
    };

    pub const OTP_SCRAMBLE_CHECK: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-otp-scramble-check",
        bin_name: "caliptra-mcu-test-fw-otp-scramble-check",
        features: &["emu"],
    };

    pub const LC_CTRL: FwId = FwId {
        crate_name: "caliptra-mcu-test-fw-lc-ctrl",
        bin_name: "caliptra-mcu-test-fw-lc-ctrl",
        features: &["emu"],
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &hw_model_tests::MAILBOX_RESPONDER,
    &hw_model_tests::HITLESS_UPDATE_FLOW,
    &hw_model_tests::AXI_BYPASS,
    &hw_model_tests::EXCEPTION_HANDLER,
    &hw_model_tests::USB_RESPONDER,
    &hw_model_tests::USB_OCP_RECOVERY,
    &hw_model_tests::SW_DIGEST_LOCK,
    &hw_model_tests::OTP_BLANK_CHECK,
    &hw_model_tests::OTP_SCRAMBLE_CHECK,
    &hw_model_tests::LC_CTRL,
];

pub const CPTRA_REGISTERED_FW: &[&FwId] = &[
    &caliptra_builder::firmware::hw_model_tests::MCU_HITLESS_UPDATE_FLOW,
    &caliptra_builder::firmware::driver_tests::AXI_BYPASS,
];

/// Profile for compiling MCU firmware
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirmwareProfile {
    Devel,
    Release,
}

/// Caliptra ROM specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaliptraRomSpec {
    features: &'static [&'static str],
}

impl CaliptraRomSpec {
    pub const DEFAULT: Self = Self { features: &[] };

    pub const fn new(features: &'static [&'static str]) -> Self {
        Self { features }
    }

    pub fn features(&self) -> &'static [&'static str] {
        self.features
    }

    pub fn filename(&self) -> &'static str {
        "caliptra_rom.bin"
    }
}

/// Caliptra Runtime (RT) specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaliptraRtSpec {
    features: &'static [&'static str],
    svn: Option<u32>,
}

impl CaliptraRtSpec {
    pub const DEFAULT: Self = Self {
        features: &[],
        svn: None,
    };

    pub const OCP_LOCK: Self = Self {
        features: &["ocp-lock"],
        svn: None,
    };

    pub const SVN7: Self = Self {
        features: &[],
        svn: Some(7),
    };

    pub const SVN128: Self = Self {
        features: &[],
        svn: Some(128),
    };

    pub const fn new(features: &'static [&'static str], svn: Option<u32>) -> Self {
        Self { features, svn }
    }

    pub fn features(&self) -> &'static [&'static str] {
        self.features
    }

    pub fn svn(&self) -> Option<u32> {
        self.svn
    }

    pub fn filename(&self) -> &'static str {
        if self.features.contains(&"ocp-lock") {
            "caliptra_fw_ocp_lock.bin"
        } else if self.svn == Some(7) {
            "caliptra_fw_svn7.bin"
        } else if self.svn == Some(128) {
            "caliptra_fw_svn128.bin"
        } else {
            "caliptra_fw.bin"
        }
    }
}

/// MCU ROM specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McuRomSpec {
    features: &'static [&'static str],
}

impl McuRomSpec {
    pub const DEFAULT: Self = Self { features: &[] };

    pub const OCP_LOCK: Self = Self {
        features: &["ocp-lock"],
    };

    pub const fn new(features: &'static [&'static str]) -> Self {
        Self { features }
    }

    pub fn features(&self) -> &'static [&'static str] {
        self.features
    }

    pub fn filename(&self) -> String {
        if let Some(&rom_feature) = self.features.first() {
            format!("mcu-test-rom-feature-{rom_feature}.bin")
        } else {
            "mcu_rom.bin".to_string()
        }
    }
}

/// MCU Firmware (Runtime) specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McuFwSpec {
    id: &'static str,
    features: &'static [&'static str],
    profile: FirmwareProfile,
    example_app: bool,
}

impl McuFwSpec {
    pub const fn new(
        id: &'static str,
        features: &'static [&'static str],
        profile: FirmwareProfile,
        example_app: bool,
    ) -> Self {
        Self {
            id,
            features,
            profile,
            example_app,
        }
    }

    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn features(&self) -> &'static [&'static str] {
        self.features
    }

    pub fn profile(&self) -> FirmwareProfile {
        self.profile
    }

    pub fn example_app(&self) -> bool {
        self.example_app
    }

    pub fn filename(&self) -> String {
        if self.id == "caliptra-mcu-bare-metal"
            || self.id == "caliptra-mcu-provisioning-test-unlocked-fw"
        {
            format!("bare_metal/{}.bin", self.id)
        } else {
            format!("mcu-test-runtime-{}.bin", self.id)
        }
    }

    pub fn flash_image_filename(&self) -> String {
        format!("mcu-test-flash-image-{}.bin", self.id)
    }

    pub fn pldm_fw_pkg_filename(&self) -> String {
        format!("mcu-test-pldm-fw-pkg-{}.bin", self.id)
    }

    pub fn update_flash_image_filename(&self) -> String {
        format!("mcu-test-update-flash-image-{}.bin", self.id)
    }

    pub fn user_app_elf_filename(&self) -> String {
        format!("mcu-test-user-app-elf-{}.bin", self.id)
    }
}

/// SoC Manifest specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocManifestSpec {
    id: &'static str,
}

impl SocManifestSpec {
    pub const DEFAULT: Self = Self { id: "default" };

    pub const fn new(id: &'static str) -> Self {
        Self { id }
    }

    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn filename(&self) -> String {
        format!("mcu-test-soc-manifest-{}.bin", self.id)
    }
}

/// Target execution platform filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetPlatform {
    Emulator,
    Fpga,
    All,
}

/// A complete target combining all components of the firmware stack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FirmwareTarget {
    id: &'static str,
    platform: TargetPlatform,
    caliptra_rom: CaliptraRomSpec,
    caliptra_rt: CaliptraRtSpec,
    mcu_rom: McuRomSpec,
    mcu_fw: McuFwSpec,
    soc_manifest: SocManifestSpec,
    caliptra_rom_filename: &'static str,
    caliptra_rt_filename: &'static str,
    mcu_rom_filename: &'static str,
    mcu_fw_filename: &'static str,
    soc_manifest_filename: &'static str,
    flash_image_filename: &'static str,
    pldm_fw_pkg_filename: &'static str,
    update_flash_image_filename: Option<&'static str>,
    user_app_elf_filename: &'static str,
}

impl FirmwareTarget {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: &'static str,
        platform: TargetPlatform,
        caliptra_rom: CaliptraRomSpec,
        caliptra_rt: CaliptraRtSpec,
        mcu_rom: McuRomSpec,
        mcu_fw: McuFwSpec,
        soc_manifest: SocManifestSpec,
        caliptra_rom_filename: &'static str,
        caliptra_rt_filename: &'static str,
        mcu_rom_filename: &'static str,
        mcu_fw_filename: &'static str,
        soc_manifest_filename: &'static str,
        flash_image_filename: &'static str,
        pldm_fw_pkg_filename: &'static str,
        update_flash_image_filename: Option<&'static str>,
        user_app_elf_filename: &'static str,
    ) -> Self {
        Self {
            id,
            platform,
            caliptra_rom,
            caliptra_rt,
            mcu_rom,
            mcu_fw,
            soc_manifest,
            caliptra_rom_filename,
            caliptra_rt_filename,
            mcu_rom_filename,
            mcu_fw_filename,
            soc_manifest_filename,
            flash_image_filename,
            pldm_fw_pkg_filename,
            update_flash_image_filename,
            user_app_elf_filename,
        }
    }

    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn platform(&self) -> TargetPlatform {
        self.platform
    }

    pub fn caliptra_rom_spec(&self) -> &CaliptraRomSpec {
        &self.caliptra_rom
    }

    pub fn caliptra_rt_spec(&self) -> &CaliptraRtSpec {
        &self.caliptra_rt
    }

    pub fn mcu_rom_spec(&self) -> &McuRomSpec {
        &self.mcu_rom
    }

    pub fn mcu_fw_spec(&self) -> &McuFwSpec {
        &self.mcu_fw
    }

    pub fn soc_manifest_spec(&self) -> &SocManifestSpec {
        &self.soc_manifest
    }

    pub fn example_app(&self) -> bool {
        self.mcu_fw.example_app
    }

    pub fn caliptra_rom_filename(&self) -> &'static str {
        self.caliptra_rom_filename
    }

    pub fn caliptra_rt_filename(&self) -> &'static str {
        self.caliptra_rt_filename
    }

    pub fn mcu_rom_filename(&self) -> &'static str {
        self.mcu_rom_filename
    }

    pub fn mcu_fw_filename(&self) -> &'static str {
        self.mcu_fw_filename
    }

    pub fn flash_image_filename(&self) -> &'static str {
        self.flash_image_filename
    }

    pub fn pldm_fw_pkg_filename(&self) -> &'static str {
        self.pldm_fw_pkg_filename
    }

    pub fn update_flash_image_filename(&self) -> Option<&'static str> {
        self.update_flash_image_filename
    }

    pub fn user_app_elf_filename(&self) -> &'static str {
        self.user_app_elf_filename
    }

    pub fn soc_manifest_filename(&self) -> &'static str {
        self.soc_manifest_filename
    }

    pub fn supports_platform(&self, platform: &str) -> bool {
        matches!(
            (self.platform, platform),
            (TargetPlatform::All, _)
                | (TargetPlatform::Emulator, "emulator")
                | (TargetPlatform::Fpga, "fpga")
        )
    }
}

pub mod targets {
    use super::*;
    use crate::all::FirmwareBinaries;

    macro_rules! default_fw_bundle {
        ($name:ident, $id:expr) => {
            pub const $name: FirmwareTarget = FirmwareTarget {
                id: $id,
                platform: TargetPlatform::All,
                caliptra_rom: CaliptraRomSpec::DEFAULT,
                caliptra_rt: CaliptraRtSpec::DEFAULT,
                mcu_rom: McuRomSpec::DEFAULT,
                mcu_fw: McuFwSpec {
                    id: $id,
                    features: &[$id],
                    profile: FirmwareProfile::Devel,
                    example_app: false,
                },
                soc_manifest: SocManifestSpec { id: $id },
                caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
                caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_NAME,
                mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
                mcu_fw_filename: FirmwareBinaries::MCU_RUNTIME_NAME,
                soc_manifest_filename: FirmwareBinaries::SOC_MANIFEST_NAME,
                flash_image_filename: FirmwareBinaries::FLASH_IMAGE_NAME,
                pldm_fw_pkg_filename: FirmwareBinaries::PLDM_FW_PKG_NAME,
                update_flash_image_filename: None,
                user_app_elf_filename: FirmwareBinaries::USER_APP_ELF_NAME,
            };
        };
    }

    macro_rules! fw_bundle {
        ($name:ident, $id:expr, $example_app:expr) => {
            pub const $name: FirmwareTarget = FirmwareTarget {
                id: $id,
                platform: TargetPlatform::All,
                caliptra_rom: CaliptraRomSpec::DEFAULT,
                caliptra_rt: CaliptraRtSpec::DEFAULT,
                mcu_rom: McuRomSpec::DEFAULT,
                mcu_fw: McuFwSpec {
                    id: $id,
                    features: &[$id],
                    profile: FirmwareProfile::Devel,
                    example_app: $example_app,
                },
                soc_manifest: SocManifestSpec { id: $id },
                caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
                caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_NAME,
                mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
                mcu_fw_filename: concat!("mcu-test-runtime-", $id, ".bin"),
                soc_manifest_filename: concat!("mcu-test-soc-manifest-", $id, ".bin"),
                flash_image_filename: concat!("mcu-test-flash-image-", $id, ".bin"),
                pldm_fw_pkg_filename: concat!("mcu-test-pldm-fw-pkg-", $id, ".bin"),
                update_flash_image_filename: Some(concat!(
                    "mcu-test-update-flash-image-",
                    $id,
                    ".bin"
                )),
                user_app_elf_filename: concat!("mcu-test-user-app-elf-", $id, ".bin"),
            };
        };
    }

    macro_rules! bare_metal_fw_bundle {
        ($name:ident, $id:expr) => {
            pub const $name: FirmwareTarget = FirmwareTarget {
                id: $id,
                platform: TargetPlatform::All,
                caliptra_rom: CaliptraRomSpec::DEFAULT,
                caliptra_rt: CaliptraRtSpec::DEFAULT,
                mcu_rom: McuRomSpec::DEFAULT,
                mcu_fw: McuFwSpec {
                    id: $id,
                    features: &[$id],
                    profile: FirmwareProfile::Devel,
                    example_app: false,
                },
                soc_manifest: SocManifestSpec { id: $id },
                caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
                caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_NAME,
                mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
                mcu_fw_filename: concat!("bare_metal/", $id, ".bin"),
                soc_manifest_filename: concat!("mcu-test-soc-manifest-", $id, ".bin"),
                flash_image_filename: concat!("mcu-test-flash-image-", $id, ".bin"),
                pldm_fw_pkg_filename: concat!("mcu-test-pldm-fw-pkg-", $id, ".bin"),
                update_flash_image_filename: Some(concat!(
                    "mcu-test-update-flash-image-",
                    $id,
                    ".bin"
                )),
                user_app_elf_filename: concat!("mcu-test-user-app-elf-", $id, ".bin"),
            };
        };
    }

    fw_bundle!(TEST_ACTIVE_I3C1, "active-i3c1", false);
    fw_bundle!(TEST_I3C_SIMPLE, "test-i3c-simple", false);
    fw_bundle!(TEST_I3C_CONSTANT_WRITES, "test-i3c-constant-writes", false);
    fw_bundle!(
        TEST_MCTP_CAPSULE_LOOPBACK,
        "test-mctp-capsule-loopback",
        false
    );
    fw_bundle!(
        TEST_FIRMWARE_UPDATE_STREAMING,
        "test-firmware-update-streaming",
        false
    );
    fw_bundle!(
        TEST_STREAMING_BOOT_FLASH_WRITE_BACK,
        "test-streaming-boot-flash-write-back",
        false
    );
    fw_bundle!(
        TEST_FIRMWARE_UPDATE_FLASH,
        "test-firmware-update-flash",
        false
    );
    fw_bundle!(TEST_FLASH_BASED_BOOT, "test-flash-based-boot", false);
    fw_bundle!(TEST_PLDM_STREAMING_BOOT, "test-pldm-streaming-boot", false);
    fw_bundle!(TEST_PLDM_FW_UPDATE_E2E, "test-pldm-fw-update-e2e", false);
    default_fw_bundle!(TEST_DO_NOTHING, "test-do-nothing");
    fw_bundle!(TEST_CALIPTRA_CERTS, "test-caliptra-certs", true);
    fw_bundle!(TEST_CALIPTRA_CRYPTO, "test-caliptra-crypto", true);
    fw_bundle!(TEST_CALIPTRA_MAILBOX, "test-caliptra-mailbox", true);
    fw_bundle!(TEST_DMA, "test-dma", true);
    fw_bundle!(
        TEST_DOE_TRANSPORT_LOOPBACK,
        "test-doe-transport-loopback",
        true
    );
    fw_bundle!(TEST_DOE_USER_LOOPBACK, "test-doe-user-loopback", true);
    fw_bundle!(TEST_DOE_DISCOVERY, "test-doe-discovery", true);
    fw_bundle!(TEST_GET_DEVICE_STATE, "test-get-device-state", true);
    fw_bundle!(TEST_FLASH_CTRL_INIT, "test-flash-ctrl-init", false);
    fw_bundle!(
        TEST_FLASH_CTRL_READ_WRITE_PAGE,
        "test-flash-ctrl-read-write-page",
        false
    );
    fw_bundle!(
        TEST_FLASH_CTRL_ERASE_PAGE,
        "test-flash-ctrl-erase-page",
        false
    );
    fw_bundle!(
        TEST_FLASH_STORAGE_READ_WRITE,
        "test-flash-storage-read-write",
        false
    );
    fw_bundle!(TEST_FLASH_STORAGE_ERASE, "test-flash-storage-erase", false);
    fw_bundle!(TEST_FLASH_USERMODE, "test-flash-usermode", true);
    fw_bundle!(TEST_LOG_FLASH_CIRCULAR, "test-log-flash-circular", false);
    fw_bundle!(TEST_LOG_FLASH_LINEAR, "test-log-flash-linear", false);
    fw_bundle!(TEST_LOG_FLASH_USERMODE, "test-log-flash-usermode", true);
    fw_bundle!(
        TEST_DEFMT_LOGGING_MAILBOX,
        "test-defmt-logging-mailbox",
        false
    );
    fw_bundle!(TEST_DEFMT_LOGGING_VDM, "test-defmt-logging-vdm", false);
    fw_bundle!(TEST_MCTP_CTRL_CMDS, "test-mctp-ctrl-cmds", false);
    fw_bundle!(TEST_MCTP_USER_LOOPBACK, "test-mctp-user-loopback", true);
    fw_bundle!(TEST_MCTP_VDM_CMDS, "test-mctp-vdm-cmds", false);
    fw_bundle!(TEST_PLDM_DISCOVERY, "test-pldm-discovery", false);
    fw_bundle!(TEST_PLDM_FW_UPDATE, "test-pldm-fw-update", false);
    fw_bundle!(TEST_MCI, "test-mci", true);
    fw_bundle!(TEST_MCU_MBOX_DRIVER, "test-mcu-mbox-driver", false);
    fw_bundle!(
        TEST_MCU_MBOX_SOC_REQUESTER_LOOPBACK,
        "test-mcu-mbox-soc-requester-loopback",
        true
    );
    fw_bundle!(TEST_MCU_MBOX_CMDS, "test-mcu-mbox-cmds", false);
    fw_bundle!(TEST_MBOX_SRAM, "test-mbox-sram", true);
    fw_bundle!(TEST_EXTERNAL_OTP, "test-external-otp", true);
    fw_bundle!(TEST_HANDOFF, "test-handoff", false);
    fw_bundle!(TEST_DPE_HANDLE_STORE, "test-dpe-handle-store", true);
    fw_bundle!(TEST_SW_PCR_STORE, "test-sw-pcr-store", true);
    fw_bundle!(TEST_WARM_RESET, "test-warm-reset", true);
    fw_bundle!(TEST_EXIT_IMMEDIATELY, "test-exit-immediately", false);
    fw_bundle!(
        TEST_MCU_ROM_FLASH_ACCESS,
        "test-mcu-rom-flash-access",
        false
    );
    macro_rules! rom_feature_fw_bundle {
        ($name:ident, $id:expr, $feature:expr) => {
            pub const $name: FirmwareTarget = FirmwareTarget {
                id: $id,
                platform: TargetPlatform::All,
                caliptra_rom: CaliptraRomSpec::DEFAULT,
                caliptra_rt: CaliptraRtSpec::DEFAULT,
                mcu_rom: McuRomSpec {
                    features: &[$feature],
                },
                mcu_fw: McuFwSpec {
                    id: $id,
                    features: &[],
                    profile: FirmwareProfile::Devel,
                    example_app: false,
                },
                soc_manifest: SocManifestSpec { id: $id },
                caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
                caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_NAME,
                mcu_rom_filename: concat!("mcu-test-rom-feature-", $feature, ".bin"),
                mcu_fw_filename: concat!("mcu-test-runtime-", $id, ".bin"),
                soc_manifest_filename: concat!("mcu-test-soc-manifest-", $id, ".bin"),
                flash_image_filename: concat!("mcu-test-flash-image-", $id, ".bin"),
                pldm_fw_pkg_filename: concat!("mcu-test-pldm-fw-pkg-", $id, ".bin"),
                update_flash_image_filename: Some(concat!(
                    "mcu-test-update-flash-image-",
                    $id,
                    ".bin"
                )),
                user_app_elf_filename: concat!("mcu-test-user-app-elf-", $id, ".bin"),
            };
        };
    }

    macro_rules! rom_fw_bundle {
        ($name:ident, $id:expr) => {
            pub const $name: FirmwareTarget = FirmwareTarget {
                id: $id,
                platform: TargetPlatform::All,
                caliptra_rom: CaliptraRomSpec::DEFAULT,
                caliptra_rt: CaliptraRtSpec::DEFAULT,
                mcu_rom: McuRomSpec::DEFAULT,
                mcu_fw: McuFwSpec {
                    id: $id,
                    features: &[],
                    profile: FirmwareProfile::Devel,
                    example_app: false,
                },
                soc_manifest: SocManifestSpec { id: $id },
                caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
                caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_NAME,
                mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
                mcu_fw_filename: concat!("mcu-test-runtime-", $id, ".bin"),
                soc_manifest_filename: concat!("mcu-test-soc-manifest-", $id, ".bin"),
                flash_image_filename: concat!("mcu-test-flash-image-", $id, ".bin"),
                pldm_fw_pkg_filename: concat!("mcu-test-pldm-fw-pkg-", $id, ".bin"),
                update_flash_image_filename: Some(concat!(
                    "mcu-test-update-flash-image-",
                    $id,
                    ".bin"
                )),
                user_app_elf_filename: concat!("mcu-test-user-app-elf-", $id, ".bin"),
            };
        };
    }

    rom_feature_fw_bundle!(TEST_I3C_SERVICES, "test-i3c-services", "test-i3c-services");
    rom_feature_fw_bundle!(TEST_ROM_HOOKS, "test-rom-hooks", "test-rom-hooks");
    rom_feature_fw_bundle!(TEST_DOT_RECOVERY, "test-dot-recovery", "test-dot-recovery");
    rom_feature_fw_bundle!(
        TEST_DOT_RECOVERY_RESET_FLOW,
        "test-dot-recovery-reset-flow",
        "test-dot-recovery-reset-flow"
    );
    rom_fw_bundle!(TEST_SVN_MANIFEST, "test-svn-manifest");
    rom_fw_bundle!(TEST_STABLE_OWNER_KEY, "stable-owner-key");
    fw_bundle!(
        TEST_MCTP_SPDM_ATTESTATION,
        "test-mctp-spdm-attestation",
        false
    );
    fw_bundle!(
        TEST_MCTP_SPDM_ATTESTATION_PCR_QUOTE,
        "test-mctp-spdm-attestation-pcr-quote",
        false
    );
    fw_bundle!(
        TEST_MCTP_SPDM_RESPONDER_CONFORMANCE,
        "test-mctp-spdm-responder-conformance",
        false
    );
    fw_bundle!(
        TEST_MCTP_VDM_VALIDATOR,
        "test-caliptra-util-host-mctp-vdm-validator",
        false
    );
    rom_fw_bundle!(
        TEST_OCP_DEV_IDENTITY_PROVISION_TOOL,
        "test-ocp-dev-identity-provision-tool"
    );
    fw_bundle!(
        TEST_CALIPTRA_UTIL_HOST_SPDM_VDM_VALIDATOR,
        "test-caliptra-util-host-spdm-vdm-validator",
        false
    );
    fw_bundle!(
        TEST_CALIPTRA_UTIL_HOST_MCU_MAILBOX_VALIDATOR,
        "test-caliptra-util-host-validator",
        false
    );

    bare_metal_fw_bundle!(BARE_METAL, "caliptra-mcu-bare-metal");
    bare_metal_fw_bundle!(
        PROVISIONING_TEST_UNLOCKED_FW,
        "caliptra-mcu-provisioning-test-unlocked-fw"
    );
    rom_fw_bundle!(TEST_MAILBOX_RESPONDER, "mcu-test-rom-caliptra-mcu-test-fw-mailbox-responder-caliptra-mcu-test-fw-mailbox-responder");
    rom_fw_bundle!(TEST_HITLESS_UPDATE_FLOW, "mcu-test-rom-caliptra-mcu-test-fw-hitless-update-flow-caliptra-mcu-test-fw-hitless-update-flow");
    rom_fw_bundle!(
        TEST_AXI_BYPASS,
        "mcu-test-rom-caliptra-mcu-test-fw-axi-bypass-caliptra-mcu-test-fw-axi-bypass"
    );
    rom_fw_bundle!(TEST_EXCEPTION_HANDLER, "mcu-test-rom-caliptra-mcu-test-fw-exception-handler-caliptra-mcu-test-fw-exception-handler");
    rom_fw_bundle!(
        TEST_USB_RESPONDER,
        "mcu-test-rom-caliptra-mcu-test-fw-usb-responder-caliptra-mcu-test-fw-usb-responder"
    );
    rom_fw_bundle!(TEST_USB_OCP_RECOVERY, "test-usb-ocp-recovery");
    rom_fw_bundle!(
        TEST_SW_DIGEST_LOCK,
        "mcu-test-rom-caliptra-mcu-test-fw-sw-digest-lock-caliptra-mcu-test-fw-sw-digest-lock"
    );
    rom_fw_bundle!(
        TEST_OTP_BLANK_CHECK,
        "mcu-test-rom-caliptra-mcu-test-fw-otp-blank-check-caliptra-mcu-test-fw-otp-blank-check"
    );
    rom_fw_bundle!(TEST_OTP_SCRAMBLE_CHECK, "mcu-test-rom-caliptra-mcu-test-fw-otp-scramble-check-caliptra-mcu-test-fw-otp-scramble-check");
    rom_fw_bundle!(
        TEST_LC_CTRL,
        "mcu-test-rom-caliptra-mcu-test-fw-lc-ctrl-caliptra-mcu-test-fw-lc-ctrl"
    );

    pub const TEST_DEFMT_LOGGING_RELEASE: FirmwareTarget = FirmwareTarget {
        id: "test-defmt-logging-release",
        platform: TargetPlatform::All,
        caliptra_rom: CaliptraRomSpec::DEFAULT,
        caliptra_rt: CaliptraRtSpec::DEFAULT,
        mcu_rom: McuRomSpec::DEFAULT,
        mcu_fw: McuFwSpec {
            id: "test-defmt-logging-release",
            features: &["test-defmt-logging-release", "release"],
            profile: FirmwareProfile::Release,
            example_app: false,
        },
        soc_manifest: SocManifestSpec {
            id: "test-defmt-logging-release",
        },
        caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
        caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_NAME,
        mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
        mcu_fw_filename: "mcu-test-runtime-test-defmt-logging-release.bin",
        soc_manifest_filename: "mcu-test-soc-manifest-test-defmt-logging-release.bin",
        flash_image_filename: "mcu-test-flash-image-test-defmt-logging-release.bin",
        pldm_fw_pkg_filename: "mcu-test-pldm-fw-pkg-test-defmt-logging-release.bin",
        update_flash_image_filename: Some(
            "mcu-test-update-flash-image-test-defmt-logging-release.bin",
        ),
        user_app_elf_filename: "mcu-test-user-app-elf-test-defmt-logging-release.bin",
    };

    pub const TEST_OCP_LOCK: FirmwareTarget = FirmwareTarget {
        id: "test-ocp-lock",
        platform: TargetPlatform::All,
        caliptra_rom: CaliptraRomSpec::DEFAULT,
        caliptra_rt: CaliptraRtSpec::OCP_LOCK,
        mcu_rom: McuRomSpec::OCP_LOCK,
        mcu_fw: McuFwSpec {
            id: "test-ocp-lock",
            features: &["test-ocp-lock"],
            profile: FirmwareProfile::Devel,
            example_app: true,
        },
        soc_manifest: SocManifestSpec {
            id: "test-ocp-lock",
        },
        caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
        caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_OCP_LOCK_NAME,
        mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
        mcu_fw_filename: "mcu-test-runtime-test-ocp-lock.bin",
        soc_manifest_filename: "mcu-test-soc-manifest-test-ocp-lock.bin",
        flash_image_filename: "mcu-test-flash-image-test-ocp-lock.bin",
        pldm_fw_pkg_filename: "mcu-test-pldm-fw-pkg-test-ocp-lock.bin",
        update_flash_image_filename: Some("mcu-test-update-flash-image-test-ocp-lock.bin"),
        user_app_elf_filename: "mcu-test-user-app-elf-test-ocp-lock.bin",
    };

    pub const TEST_MCU_SVN_GT_FUSE: FirmwareTarget = FirmwareTarget {
        id: "test-mcu-svn-gt-fuse",
        platform: TargetPlatform::All,
        caliptra_rom: CaliptraRomSpec::DEFAULT,
        caliptra_rt: CaliptraRtSpec::SVN7,
        mcu_rom: McuRomSpec::DEFAULT,
        mcu_fw: McuFwSpec {
            id: "test-mcu-svn-gt-fuse",
            features: &[],
            profile: FirmwareProfile::Devel,
            example_app: false,
        },
        soc_manifest: SocManifestSpec {
            id: "test-mcu-svn-gt-fuse",
        },
        caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
        caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_SVN7_NAME,
        mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
        mcu_fw_filename: "mcu-test-runtime-test-mcu-svn-gt-fuse.bin",
        soc_manifest_filename: "mcu-test-soc-manifest-test-mcu-svn-gt-fuse.bin",
        flash_image_filename: "mcu-test-flash-image-test-mcu-svn-gt-fuse.bin",
        pldm_fw_pkg_filename: "mcu-test-pldm-fw-pkg-test-mcu-svn-gt-fuse.bin",
        update_flash_image_filename: Some("mcu-test-update-flash-image-test-mcu-svn-gt-fuse.bin"),
        user_app_elf_filename: "mcu-test-user-app-elf-test-mcu-svn-gt-fuse.bin",
    };

    pub const TEST_MCU_SVN_LT_FUSE: FirmwareTarget = FirmwareTarget {
        id: "test-mcu-svn-lt-fuse",
        platform: TargetPlatform::All,
        caliptra_rom: CaliptraRomSpec::DEFAULT,
        caliptra_rt: CaliptraRtSpec::SVN128,
        mcu_rom: McuRomSpec::DEFAULT,
        mcu_fw: McuFwSpec {
            id: "test-mcu-svn-lt-fuse",
            features: &[],
            profile: FirmwareProfile::Devel,
            example_app: false,
        },
        soc_manifest: SocManifestSpec {
            id: "test-mcu-svn-lt-fuse",
        },
        caliptra_rom_filename: FirmwareBinaries::CALIPTRA_ROM_NAME,
        caliptra_rt_filename: FirmwareBinaries::CALIPTRA_FW_SVN128_NAME,
        mcu_rom_filename: FirmwareBinaries::MCU_ROM_NAME,
        mcu_fw_filename: "mcu-test-runtime-test-mcu-svn-lt-fuse.bin",
        soc_manifest_filename: "mcu-test-soc-manifest-test-mcu-svn-lt-fuse.bin",
        flash_image_filename: "mcu-test-flash-image-test-mcu-svn-lt-fuse.bin",
        pldm_fw_pkg_filename: "mcu-test-pldm-fw-pkg-test-mcu-svn-lt-fuse.bin",
        update_flash_image_filename: Some("mcu-test-update-flash-image-test-mcu-svn-lt-fuse.bin"),
        user_app_elf_filename: "mcu-test-user-app-elf-test-mcu-svn-lt-fuse.bin",
    };

    pub const FIRMWARE_TARGETS: &[&FirmwareTarget] = &[
        &TEST_ACTIVE_I3C1,
        &TEST_I3C_SIMPLE,
        &TEST_I3C_CONSTANT_WRITES,
        &TEST_MCTP_CAPSULE_LOOPBACK,
        &TEST_FIRMWARE_UPDATE_STREAMING,
        &TEST_STREAMING_BOOT_FLASH_WRITE_BACK,
        &TEST_FIRMWARE_UPDATE_FLASH,
        &TEST_FLASH_BASED_BOOT,
        &TEST_PLDM_STREAMING_BOOT,
        &TEST_PLDM_FW_UPDATE_E2E,
        &TEST_DO_NOTHING,
        &TEST_CALIPTRA_CERTS,
        &TEST_CALIPTRA_CRYPTO,
        &TEST_CALIPTRA_MAILBOX,
        &TEST_DMA,
        &TEST_DOE_TRANSPORT_LOOPBACK,
        &TEST_DOE_USER_LOOPBACK,
        &TEST_DOE_DISCOVERY,
        &TEST_GET_DEVICE_STATE,
        &TEST_FLASH_CTRL_INIT,
        &TEST_FLASH_CTRL_READ_WRITE_PAGE,
        &TEST_FLASH_CTRL_ERASE_PAGE,
        &TEST_FLASH_STORAGE_READ_WRITE,
        &TEST_FLASH_STORAGE_ERASE,
        &TEST_FLASH_USERMODE,
        &TEST_LOG_FLASH_CIRCULAR,
        &TEST_LOG_FLASH_LINEAR,
        &TEST_LOG_FLASH_USERMODE,
        &TEST_DEFMT_LOGGING_MAILBOX,
        &TEST_DEFMT_LOGGING_RELEASE,
        &TEST_DEFMT_LOGGING_VDM,
        &TEST_MCTP_CTRL_CMDS,
        &TEST_MCTP_USER_LOOPBACK,
        &TEST_MCTP_VDM_CMDS,
        &TEST_PLDM_DISCOVERY,
        &TEST_PLDM_FW_UPDATE,
        &TEST_MCI,
        &TEST_MCU_MBOX_DRIVER,
        &TEST_MCU_MBOX_SOC_REQUESTER_LOOPBACK,
        &TEST_MCU_MBOX_CMDS,
        &TEST_MBOX_SRAM,
        &TEST_EXTERNAL_OTP,
        &TEST_HANDOFF,
        &TEST_DPE_HANDLE_STORE,
        &TEST_SW_PCR_STORE,
        &TEST_WARM_RESET,
        &TEST_OCP_LOCK,
        &TEST_EXIT_IMMEDIATELY,
        &TEST_MCU_ROM_FLASH_ACCESS,
        &TEST_MCU_SVN_GT_FUSE,
        &TEST_MCU_SVN_LT_FUSE,
        &TEST_USB_OCP_RECOVERY,
        &TEST_I3C_SERVICES,
        &TEST_ROM_HOOKS,
        &TEST_DOT_RECOVERY,
        &TEST_DOT_RECOVERY_RESET_FLOW,
        &TEST_SVN_MANIFEST,
        &TEST_STABLE_OWNER_KEY,
        &TEST_MCTP_SPDM_ATTESTATION,
        &TEST_MCTP_SPDM_ATTESTATION_PCR_QUOTE,
        &TEST_MCTP_SPDM_RESPONDER_CONFORMANCE,
        &TEST_MCTP_VDM_VALIDATOR,
        &TEST_OCP_DEV_IDENTITY_PROVISION_TOOL,
        &TEST_CALIPTRA_UTIL_HOST_SPDM_VDM_VALIDATOR,
        &TEST_CALIPTRA_UTIL_HOST_MCU_MAILBOX_VALIDATOR,
        &BARE_METAL,
        &PROVISIONING_TEST_UNLOCKED_FW,
        &TEST_MAILBOX_RESPONDER,
        &TEST_HITLESS_UPDATE_FLOW,
        &TEST_AXI_BYPASS,
        &TEST_EXCEPTION_HANDLER,
        &TEST_USB_RESPONDER,
        &TEST_SW_DIGEST_LOCK,
        &TEST_OTP_BLANK_CHECK,
        &TEST_OTP_SCRAMBLE_CHECK,
        &TEST_LC_CTRL,
    ];
}
