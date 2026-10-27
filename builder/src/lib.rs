// Licensed under the Apache-2.0 license

mod all;
mod attestation_manifest;
mod caliptra;
pub mod features;
pub mod firmware;
pub mod flash_image;
mod network_rom;
pub mod offline_signing;
mod rom;
mod runtime;
mod utils;

pub use all::{
    all_build, emulator_build, AllBuildArgs, EmulatorBinaries, EmulatorBuildArgs, FirmwareBinaries,
};
pub use caliptra::{AuthManifestOwnerConfig, AuthManifestPubKeysPaths, CaliptraBuilder, ImageCfg};
pub use network_rom::network_rom_build;
pub use offline_signing::*;
pub use rom::{append_rom_digest, rom_build, rom_size_for_platform, test_rom_build};
pub use runtime::{bare_metal_build, runtime_build_with_apps};

#[derive(Default, Clone)]
pub struct CaliptraBuildArgs<'a> {
    pub fpga: bool,
    pub ocp_lock: bool,
    pub platform: Option<&'a str>,
    pub features: Option<&'a str>,
    pub target_dir: Option<PathBuf>,
    pub fwid: Option<&'a caliptra_builder::FwId<'a>>,
    pub output_name: Option<String>,
    pub example_app: bool,
    pub svn: Option<u16>,
    /// PQC key type shared by the Caliptra firmware and authorization manifests.
    /// Defaults to LMS when not specified.
    pub pqc_key_type: Option<caliptra_image_types::FwVerificationPqcKeyType>,
    /// Cargo profile name to build with (e.g. `"release"` or `"devel"`).
    /// When `None`, builds use `release`.  Drives both the `cargo --profile
    /// <name>` invocation and the bundler manifest selection (`devel` swaps to
    /// the `*-devel.toml` platform manifest with the larger 1 MB SRAM
    /// dev-time layout; everything else falls through to the default 512 KB
    /// shipping layout).
    pub profile: Option<&'a str>,
    pub caliptra_rom: Option<PathBuf>,
    pub caliptra_firmware: Option<PathBuf>,
    pub caliptra_firmware_network_filename: Option<String>,
    pub soc_manifest: Option<PathBuf>,
    pub soc_manifest_network_filename: Option<String>,
    pub owner_auth_manifest: Option<PathBuf>,
    pub owner_measurement_policy: Option<PathBuf>,
    pub vendor_pk_hash: Option<String>,
    pub mcu_firmware: Option<PathBuf>,
    pub soc_images: Option<Vec<ImageCfg>>,
    /// Owner-only SoC images included in the Owner Authorization Manifest.
    pub owner_soc_images: Option<Vec<ImageCfg>>,
    pub mcu_image_cfg: Option<ImageCfg>,
    pub soc_manifest_svn: Option<u32>,
    pub owner_manifest_svn: Option<u32>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub offset: usize,
    /// Flash container format (1, 2, or 3). Defaults to the current format.
    pub flash_image_version: Option<u16>,
    pub output_path: Option<String>,
    pub soc_image_paths: Option<Vec<String>>,
    pub use_second_key: bool,
    pub no_default_features: bool,
    pub user_app_config_fingerprint: Option<String>,
}

use anyhow::{anyhow, Result};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
};

pub const TARGET: &str = "riscv32imc-unknown-none-elf";

pub static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
    let current_dir = std::env::current_dir().expect("Could not get current directory");
    if current_dir.join("Cargo.toml").exists() && current_dir.join("xtask").exists() {
        return current_dir;
    }
    option_env!("CARGO_MANIFEST_DIR")
        .map(|s| {
            let p = Path::new(&s);
            if p.exists() {
                p.parent()
                    .unwrap_or(current_dir.clone().as_path())
                    .to_path_buf()
            } else {
                current_dir.clone()
            }
        })
        .unwrap_or(current_dir)
});

pub fn target_dir() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PROJECT_ROOT.join("target"))
}

pub fn hardware_revision() -> Result<caliptra_mcu_hw_revision::HardwareRevision> {
    caliptra_mcu_hw_revision::HardwareRevision::from_env().map_err(anyhow::Error::msg)
}

/// Name cached and packaged artifacts independently of Cargo's compilation cache.
pub fn revisioned_name(name: &str) -> Result<String> {
    Ok(match hardware_revision()? {
        caliptra_mcu_hw_revision::HardwareRevision::V2_1 => name.to_owned(),
        revision => revision.cache_name(name),
    })
}

/// Record source identities, not a claim that different hardware pins are equivalent.
pub fn hardware_provenance() -> Result<String> {
    let revision = hardware_revision()?;
    let hardware = PROJECT_ROOT.join(revision.hardware_path());
    let git_revision = |directory: &Path| -> Result<String> {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(directory)
            .output()?;
        if !output.status.success() {
            return Err(anyhow!(
                "Cannot read hardware/source revision in {}: {}",
                directory.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    };
    let submodules = Command::new("git")
        .args(["submodule", "status", "--recursive"])
        .current_dir(&hardware)
        .output()?;
    if !submodules.status.success() {
        return Err(anyhow!(
            "Cannot read nested hardware revisions: {}",
            String::from_utf8_lossy(&submodules.stderr)
        ));
    }
    let core_root = caliptra_sw_workspace_root();
    let core_revision = git_revision(&core_root)?;
    let rom_source = std::env::var("CALIPTRA_ROM_REF")
        .map(|value| format!("separate caliptra-sw ref {value}"))
        .unwrap_or_else(|_| format!("Cargo caliptra-sw {core_revision}"));
    Ok(format!(
        "CALIPTRA_HW_REV={revision}\nMCU source={}\nMCU subsystem={} {}\n\
         Nested MCU hardware:\n{}\nCaliptra FMC/runtime source={core_revision}\n\
         Caliptra ROM source={rom_source}\nCPTRA_CI_ROM_VERSION={}\n\
         CPTRA_ROM_TYPE={}\nCALIPTRA_PREBUILT_FW_DIR={}\n\
         Core hardware pins (not assumed identical to MCU pins):\n{}",
        git_revision(&PROJECT_ROOT)?,
        revision.hardware_path(),
        git_revision(&hardware)?,
        String::from_utf8(submodules.stdout)?,
        std::env::var("CPTRA_CI_ROM_VERSION").unwrap_or_else(|_| "source build".into()),
        std::env::var("CPTRA_ROM_TYPE").unwrap_or_else(|_| "ROM_WITH_UART".into()),
        std::env::var("CALIPTRA_PREBUILT_FW_DIR").unwrap_or_else(|_| "unset".into()),
        {
            let output = Command::new("git")
                .args([
                    "ls-tree",
                    "HEAD",
                    "hw/latest/caliptra-ss",
                    "hw/rev-2_1/caliptra-ss",
                ])
                .current_dir(core_root)
                .output()?;
            if !output.status.success() {
                return Err(anyhow!("Cannot read core hardware pins"));
            }
            String::from_utf8(output.stdout)?
        }
    ))
}

pub fn write_hardware_provenance(binary: &Path) -> Result<()> {
    let mut name = binary.as_os_str().to_os_string();
    name.push(".provenance.txt");
    std::fs::write(PathBuf::from(name), hardware_provenance()?)?;
    Ok(())
}

/// Returns the Path to the caliptra-sw workspace root.
pub fn caliptra_sw_workspace_root() -> PathBuf {
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let package = metadata
        .packages
        .iter()
        .find(|p| {
            p.name.as_ref() == "caliptra-image-fake-keys" || p.name.as_ref() == "caliptra-api-types"
        })
        .map(|p| p.manifest_path.clone())
        .and_then(|p| p.ancestors().nth(3).map(|p| p.to_path_buf()));
    match package {
        Some(path) => path.into(),
        None => panic!("Could not determine caliptra-sw path"),
    }
}

pub(crate) static SYSROOT: LazyLock<String> = LazyLock::new(|| {
    // cache this in the target directory as it seems to be very slow to call rustc
    let sysroot_file = PROJECT_ROOT.join("target").join("sysroot.txt");
    if sysroot_file.exists() {
        let root = std::fs::read_to_string(&sysroot_file).unwrap();
        if PathBuf::from(&root).exists() {
            return root;
        }
    }
    // slow path
    let tock_dir = &PROJECT_ROOT
        .join("platforms")
        .join("emulator")
        .join("runtime");
    let root = String::from_utf8(
        Command::new("cargo")
            .args(["rustc", "--", "--print", "sysroot"])
            .current_dir(tock_dir)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    if root.is_empty() {
        panic!("Failed to get sysroot");
    }
    // write to target directory as a cache
    std::fs::write(sysroot_file, root.as_bytes()).unwrap();
    root
});

// Set additional flags to produce binaries from .elf files.
// - `--strip-sections`: Remove all section and data not in segments.
// - `--strip-all`: Remove non-allocated sections outside segments.
//   `.gnu.warning*` and `.ARM.attribute` sections are not removed.
pub const OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";

pub(crate) fn find_file(dir: &str, name: &str) -> Option<PathBuf> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry.file_name() == name {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}

pub fn objcopy() -> Result<String> {
    std::env::var("OBJCOPY").map(Ok).unwrap_or_else(|_| {
        // We need to get the full path to llvm-objcopy, if it is installed.
        if let Some(llvm_size) = find_file(&SYSROOT, "llvm-objcopy") {
            Ok(llvm_size.to_str().unwrap().to_string())
        } else {
            Err(anyhow!("Could not find llvm-objcopy; perhaps you need to run `rustup component add llvm-tools` or set the OBJCOPY environment variable to where to find objcopy"))
        }
    })
}

#[allow(dead_code)]
pub(crate) fn target_binary(name: &str) -> PathBuf {
    target_dir().join(TARGET).join("release").join(name)
}
