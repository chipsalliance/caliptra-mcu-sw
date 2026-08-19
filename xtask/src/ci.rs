// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use caliptra_builder::{elf_size, FirmwareType, FwId};
use elf::endian::LittleEndian;
use size_history::{
    ArtifactBuilder, Cache, FsCache, GitHubStepSummary, GithubActionCache, HtmlTableReport,
    OutputDestination, SizeHistory, Stdout,
};
use std::path::{Path, PathBuf};
use std::{env, error::Error, fs, io};

const CACHE_FORMAT_VERSION: &str = "main-2.1-v2";

pub const MCU_KERNEL_FPGA: FwId = FwId {
    crate_name: "caliptra-mcu-runtime-fpga",
    bin_name: "caliptra-mcu-runtime-fpga",
    fw_type: FirmwareType::Source { features: &[] },
};

pub const MCU_ROM_FPGA: FwId = FwId {
    crate_name: "caliptra-mcu-rom-fpga",
    bin_name: "caliptra-mcu-rom-fpga",
    fw_type: FirmwareType::Source { features: &[] },
};

pub const MCU_USER_FPGA: FwId = FwId {
    crate_name: "user-app",
    bin_name: "user-app",
    fw_type: FirmwareType::Source { features: &[] },
};

pub(crate) fn size_history() -> Result<(), anyhow::Error> {
    let cache = create_cache().map_err(|e| anyhow::anyhow!("{}", e))?;
    let reporter = HtmlTableReport::new("https://github.com/chipsalliance/caliptra-mcu-sw");
    let output: Box<dyn OutputDestination> = if env::var("GITHUB_STEP_SUMMARY").is_ok() {
        Box::new(GitHubStepSummary)
    } else {
        Box::new(Stdout)
    };

    SizeHistory::new(reporter, output, cache)
        .worktree_path("/tmp/caliptra-mcu-size-history-wt")
        .cache_version(CACHE_FORMAT_VERSION)
        .with_pr_squashing(true)
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "Kernel size",
            MCU_KERNEL_FPGA,
            SizeType::Instruction,
            true,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "ROM size",
            MCU_ROM_FPGA,
            SizeType::Instruction,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "App size",
            MCU_USER_FPGA,
            SizeType::Instruction,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "Kernel stack size",
            MCU_KERNEL_FPGA,
            SizeType::Stack,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "User stack size",
            MCU_USER_FPGA,
            SizeType::Stack,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "App .bss size",
            MCU_USER_FPGA,
            SizeType::Bss,
            false,
        )))
        .add_builder(Box::new(SramOverflowGenerator))
        .run()
        .map_err(|e| anyhow::anyhow!("{}", e))
}

fn create_cache() -> Result<Box<dyn Cache>, Box<dyn Error>> {
    Ok(GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/caliptra-mcu-size-cache";
        eprintln!(
            "Unable to create GitHub Actions cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?)
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

fn build_runtime(target_dir: &Path) -> Result<PathBuf> {
    let lock_path = target_dir
        .parent()
        .context("size-history target directory has no workspace parent")?
        .join("Cargo.lock");
    let original_lock = fs::read(&lock_path).context("failed to snapshot Cargo.lock")?;

    // FPGA does not have a `*-devel.toml` manifest variant (HW-fixed SRAM);
    // still exercise the `release` cargo feature / `release` cargo profile
    // against its single 512 KB layout so size regressions and
    // release-only `cfg`s are caught.
    let result =
        caliptra_mcu_builder::runtime_build_with_apps(&caliptra_mcu_builder::CaliptraBuildArgs {
            platform: Some("fpga"),
            features: Some("release"),
            profile: Some("release"),
            no_default_features: true,
            target_dir: Some(target_dir.to_path_buf()),
            ..Default::default()
        });

    fs::write(&lock_path, original_lock).context("failed to restore Cargo.lock")?;
    result
}

fn get_elf_bytes(target_dir: &Path, fwid: FwId<'_>) -> io::Result<Vec<u8>> {
    fs::read(
        target_dir
            .join("riscv32imc-unknown-none-elf")
            .join("release")
            .join(fwid.bin_name),
    )
}

fn other_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

pub fn elf_stack_size(elf_bytes: &[u8]) -> io::Result<u64> {
    elf_section_size(elf_bytes, ".stack")
}

pub fn elf_bss_size(elf_bytes: &[u8]) -> io::Result<u64> {
    elf_section_size(elf_bytes, ".bss")
}

fn elf_section_size(elf_bytes: &[u8], section_name: &str) -> io::Result<u64> {
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).map_err(other_err)?;
    let Ok(Some(section)) = elf.section_header_by_name(section_name) else {
        return Err(other_err(format!("ELF file has no {section_name} section")));
    };

    let mut min_addr = u64::MAX;
    let mut max_addr = u64::MIN;

    min_addr = min_addr.min(section.sh_addr);
    max_addr = max_addr.max(section.sh_addr.saturating_add(section.sh_size));

    Ok(max_addr.saturating_sub(min_addr))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeType {
    Instruction,
    Stack,
    Bss,
}

/// Builds Caliptra firmware using runtime_build_with_apps and measures ELF size.
struct CaliptraElfSizeGenerator {
    name: String,
    fwid: FwId<'static>,
    size_type: SizeType,
    build: bool,
}

impl CaliptraElfSizeGenerator {
    fn new(name: impl Into<String>, fwid: FwId<'static>, size_type: SizeType, build: bool) -> Self {
        Self {
            name: name.into(),
            fwid,
            size_type,
            build,
        }
    }

    fn build_elf(&self, workspace: &Path) -> io::Result<u64> {
        let target_dir = workspace.join("target");

        if self.build {
            build_runtime(&target_dir).map_err(other_err)?;
        }

        let elf_bytes = get_elf_bytes(&target_dir, self.fwid)?;

        if self.size_type == SizeType::Stack {
            elf_stack_size(&elf_bytes)
        } else if self.size_type == SizeType::Bss {
            elf_bss_size(&elf_bytes)
        } else {
            elf_size(&elf_bytes)
        }
    }
}

impl ArtifactBuilder for CaliptraElfSizeGenerator {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_and_measure(&self, workspace: &Path) -> Option<u64> {
        match self.build_elf(workspace) {
            Ok(size) => Some(size),
            Err(err) => {
                eprintln!("Error building {}: {err}", self.name);
                None
            }
        }
    }
}

/// Reports how many bytes the combined kernel + user-app exceeds the FPGA SRAM
/// budget.  Returns 0 when everything fits.
struct SramOverflowGenerator;

impl SramOverflowGenerator {
    /// Run the bundler build and either:
    /// - Return 0 if it succeeds (everything fits)
    /// - Parse the overflow from the error message if it fails with
    ///   "Bytes X would exceed remaining memory space Y" → overflow = X - Y
    /// - Return None if the build fails for an unrelated reason
    fn measure(&self, workspace: &Path) -> Option<u64> {
        let target_dir = workspace.join("target");

        match build_runtime(&target_dir) {
            Ok(_) => Some(0), // Fits in SRAM
            Err(e) => {
                let msg = format!("{:?}", e);
                // Parse "Bytes <needed> would exceed remaining memory space <available>"
                parse_overflow_from_error(&msg)
            }
        }
    }
}

/// Parse the SRAM overflow from the bundler's error message.
/// Expected format: "Bytes <needed> would exceed remaining memory space <available>"
fn parse_overflow_from_error(msg: &str) -> Option<u64> {
    let bytes_prefix = "Bytes ";
    let middle = " would exceed remaining memory space ";
    let bytes_idx = msg.find(bytes_prefix)?;
    let after_bytes = &msg[bytes_idx + bytes_prefix.len()..];
    let middle_idx = after_bytes.find(middle)?;
    let needed: u64 = after_bytes[..middle_idx].trim().parse().ok()?;
    let after_middle = &after_bytes[middle_idx + middle.len()..];
    // Take digits only (stop at any non-digit)
    let available_str: String = after_middle
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let available: u64 = available_str.parse().ok()?;
    Some(needed.saturating_sub(available))
}

impl ArtifactBuilder for SramOverflowGenerator {
    fn name(&self) -> &str {
        "SRAM overflow"
    }

    fn build_and_measure(&self, workspace: &Path) -> Option<u64> {
        self.measure(workspace)
    }
}
