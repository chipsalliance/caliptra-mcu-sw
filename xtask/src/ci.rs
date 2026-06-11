// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_builder::{elf_size, FwId};
use caliptra_mcu_builder::firmware;
use elf::endian::LittleEndian;
use size_history::{
    ArtifactBuilder, Cache, FsCache, GitHubStepSummary, GithubActionCache, HtmlTableReport,
    OutputDestination, SizeHistory, Stdout,
};
use std::path::{Path, PathBuf};
use std::{env, error::Error, fs, io};

const CACHE_FORMAT_VERSION: &str = "v4";

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
            firmware::MCU_KERNEL,
            SizeType::Instruction,
            true,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "ROM size",
            firmware::MCU_ROM,
            SizeType::Instruction,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "App size",
            firmware::MCU_USER,
            SizeType::Instruction,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "Kernel stack size",
            firmware::MCU_KERNEL,
            SizeType::Stack,
            false,
        )))
        .add_builder(Box::new(CaliptraElfSizeGenerator::new(
            "User stack size",
            firmware::MCU_USER,
            SizeType::Stack,
            false,
        )))
        .run()
        .map_err(|e| anyhow::anyhow!("{}", e))
}

fn create_cache() -> Result<Box<dyn Cache>, Box<dyn Error>> {
    Ok(GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/caliptra-mcu-size-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?)
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

fn build_runtime(target_dir: &PathBuf) -> Result<PathBuf> {
    // FPGA does not have a `*-devel.toml` manifest variant (HW-fixed SRAM);
    // still exercise the `release` cargo feature / `release` cargo profile
    // against its single 512 KB layout so size regressions and
    // release-only `cfg`s are caught.
    caliptra_mcu_builder::runtime_build_with_apps(&caliptra_mcu_builder::CaliptraBuildArgs {
        platform: Some("fpga"),
        features: Some("release"),
        profile: Some("release"),
        target_dir: Some(target_dir.to_path_buf()),
        ..Default::default()
    })
}

fn get_elf_bytes<'a>(target_dir: &PathBuf, fwid: FwId<'a>) -> io::Result<Vec<u8>> {
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
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).map_err(other_err)?;
    let Ok(Some(section)) = elf.section_header_by_name(".stack") else {
        return Err(other_err("ELF file has no .stack section"));
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
