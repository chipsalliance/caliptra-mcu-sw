// Licensed under the Apache-2.0 license

//! Size history analysis tool for tracking firmware binary sizes across git history.

mod cache;
mod git;
mod process;
mod util;

use anyhow::{anyhow, Result};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::env;

use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use cache::{Cache, FsCache};
use git::{CommitInfo, WorkTree};

// Increment with non-backwards-compatible changes are made to the cache record format
const CACHE_FORMAT_VERSION: &str = "v2";

// Stack sizes from configuration (these are relatively stable across commits)
const ROM_STACK_SIZE: u64 = 0x2d00; // 11,520 bytes
const ROM_ESTACK_SIZE: u64 = 0x200; // 512 bytes
const KERNEL_STACK_SIZE: u64 = 0x2000; // 8,192 bytes
const USER_APP_STACK_SIZE: u64 = 0xae00; // 44,544 bytes
const USER_APP_MIN_RAM: u64 = 116 * 1024; // 118,784 bytes

/// Sizes tracked for each commit
#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sizes {
    /// ROM binary size (.bin file)
    pub rom_binary: Option<u64>,
    /// Kernel binary size (ELF loadable segments)
    pub kernel_binary: Option<u64>,
    /// User-app binary size (.bin file)
    pub user_app_binary: Option<u64>,
    /// Total SRAM usage: kernel + user-app + stacks + RAM allocation
    pub total_sram: Option<u64>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SizeRecord {
    pub commit: CommitInfo,
    pub sizes: Sizes,
}

/// Main entry point for size history analysis
pub fn run_size_history(output: Option<String>, max_commits: Option<usize>) -> Result<()> {
    let max_commits = max_commits.unwrap_or(50);

    // Use filesystem cache
    let cache_path = "/tmp/mcu-size-cache";
    let cache: Box<dyn Cache> = match FsCache::new(cache_path.into()) {
        Ok(c) => {
            println!("Using filesystem cache at {}", cache_path);
            Box::new(c)
        }
        Err(e) => {
            return Err(anyhow!("Failed to create cache: {}", e));
        }
    };

    let worktree_path = Path::new("/tmp/mcu-size-history-wt");

    // Clean up any existing worktree
    let _ = Command::new("git")
        .arg("worktree")
        .arg("remove")
        .arg("--force")
        .arg(worktree_path)
        .status();

    let worktree = WorkTree::new(worktree_path)?;
    let git_commits = worktree.commit_log()?;

    // Limit number of commits to process
    let git_commits: Vec<_> = git_commits.into_iter().take(max_commits).collect();

    println!("Processing {} commits...", git_commits.len());

    let mut records = vec![];
    let mut cached_commit = None;

    for commit in git_commits.iter() {
        let cache_key = format_cache_key(&commit.id);
        match cache.get(&cache_key) {
            Ok(Some(cached_records)) => {
                if let Ok(cached_records) =
                    serde_json::from_slice::<Vec<SizeRecord>>(&cached_records)
                {
                    println!("Found cache entry for remaining commits at {}", commit.id);
                    records.extend(cached_records);
                    cached_commit = Some(commit.id.clone());
                    break;
                } else {
                    println!("Error parsing cache entry");
                }
            }
            Ok(None) => {} // not found
            Err(e) => println!("Error reading from cache: {}", e),
        }

        println!(
            "Building firmware at commit {}: {}",
            &commit.id[..8],
            commit.title.lines().next().unwrap_or("")
        );

        worktree.checkout(&commit.id)?;
        worktree.submodule_update()?;

        records.push(SizeRecord {
            commit: commit.clone(),
            sizes: compute_size(&worktree, &commit.id),
        });
    }

    // Cache results
    for (i, record) in records.iter().enumerate() {
        if Some(&record.commit.id) == cached_commit.as_ref() {
            break;
        }
        if let Err(e) = cache.set(
            &format_cache_key(&record.commit.id),
            &serde_json::to_vec(&records[i..]).unwrap(),
        ) {
            println!(
                "Unable to write to cache for commit {}: {}",
                record.commit.id, e
            );
        }
    }

    let report = format_markdown_history(&records);

    // Output to file or stdout
    if let Some(output_path) = output {
        fs::write(&output_path, &report)?;
        println!("\nReport written to: {}", output_path);
    } else {
        // Check for GitHub Actions step summary
        if let Ok(summary_file) = env::var("GITHUB_STEP_SUMMARY") {
            fs::write(&summary_file, &report)?;
            println!("\nReport written to GitHub step summary");
        }
        println!("\n{}", report);
    }

    Ok(())
}

fn compute_size(worktree: &WorkTree, _commit_id: &str) -> Sizes {
    let mut sizes = Sizes::default();

    // Try to build ROM
    match build_rom_at(worktree.path) {
        Ok(rom_binary) => {
            sizes.rom_binary = Some(rom_binary);
            println!("  ROM: {} bytes", rom_binary);
        }
        Err(e) => {
            println!("  ROM build failed: {}", e);
        }
    }

    // Try to build runtime
    match build_runtime_at(worktree.path) {
        Ok((kernel_binary, user_app_binary)) => {
            sizes.kernel_binary = Some(kernel_binary);
            sizes.user_app_binary = Some(user_app_binary);

            // Calculate total SRAM usage:
            // kernel binary + kernel stack + user-app binary + user-app RAM allocation
            let total_sram = kernel_binary + KERNEL_STACK_SIZE + user_app_binary + USER_APP_MIN_RAM;
            sizes.total_sram = Some(total_sram);

            println!(
                "  Kernel: {} bytes, user-app: {} bytes, SRAM total: {} bytes",
                kernel_binary, user_app_binary, total_sram
            );
        }
        Err(e) => {
            println!("  Runtime build failed: {}", e);
        }
    }

    sizes
}

fn build_rom_at(worktree: &Path) -> io::Result<u64> {
    let status = Command::new("cargo")
        .current_dir(worktree)
        .args(["xtask", "rom-build"])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "ROM build failed"));
    }

    let rom_bin = worktree
        .join("target")
        .join("riscv32imc-unknown-none-elf")
        .join("release")
        .join("mcu-rom-emulator.bin");

    if rom_bin.exists() {
        Ok(fs::metadata(&rom_bin)?.len())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ROM binary not found",
        ))
    }
}

fn build_runtime_at(worktree: &Path) -> io::Result<(u64, u64)> {
    let status = Command::new("cargo")
        .current_dir(worktree)
        .args([
            "xtask",
            "runtime-build",
            "--features",
            "test-pldm-fw-update",
        ])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Runtime build failed"));
    }

    let target_dir = worktree
        .join("target")
        .join("riscv32imc-unknown-none-elf")
        .join("release");

    let kernel_elf = target_dir.join("mcu-runtime-emulator");
    let user_app_bin = target_dir.join("user-app-emulator.bin");

    // Get kernel binary size from ELF loadable segments (not just .text)
    let kernel_binary = if kernel_elf.exists() {
        get_elf_loadable_size(&kernel_elf).unwrap_or(0)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Kernel ELF not found",
        ));
    };

    let user_app_binary = if user_app_bin.exists() {
        fs::metadata(&user_app_bin)?.len()
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "User app binary not found",
        ));
    };

    Ok((kernel_binary, user_app_binary))
}

/// Get total size of loadable segments from ELF (actual binary size)
fn get_elf_loadable_size(elf_path: &Path) -> Option<u64> {
    let elf_bytes = fs::read(elf_path).ok()?;
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&elf_bytes).ok()?;

    // Sum up all LOAD segments
    let segments = elf.segments()?;
    let mut total = 0u64;
    for seg in segments.iter() {
        if seg.p_type == elf::abi::PT_LOAD {
            total += seg.p_filesz;
        }
    }
    Some(total)
}

fn format_cache_key(commit: &str) -> String {
    format!("{}-{}", CACHE_FORMAT_VERSION, commit)
}

/// Format a size in bytes with comma separators
fn format_size(bytes: u64) -> String {
    let s = bytes.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format the history as a Markdown table
fn format_markdown_history(records: &[SizeRecord]) -> String {
    let mut md = String::new();

    md.push_str("# MCU Firmware Size History\n\n");

    // Create extended records with deltas
    let mut extended_records = vec![];
    let mut last_sizes: Option<Sizes> = None;

    for record in records.iter().rev() {
        let ext = if let Some(ref prev) = last_sizes {
            ExtendedRecord {
                commit: record.commit.clone(),
                sizes: ExtendedSizes {
                    rom_binary: ExtendedSizeInfo::from_change(
                        prev.rom_binary,
                        record.sizes.rom_binary,
                    ),
                    kernel_binary: ExtendedSizeInfo::from_change(
                        prev.kernel_binary,
                        record.sizes.kernel_binary,
                    ),
                    user_app_binary: ExtendedSizeInfo::from_change(
                        prev.user_app_binary,
                        record.sizes.user_app_binary,
                    ),
                    total_sram: ExtendedSizeInfo::from_change(
                        prev.total_sram,
                        record.sizes.total_sram,
                    ),
                },
                is_first: false,
            }
        } else {
            ExtendedRecord {
                commit: record.commit.clone(),
                sizes: ExtendedSizes {
                    rom_binary: record
                        .sizes
                        .rom_binary
                        .map(|total| ExtendedSizeInfo { total, delta: 0 }),
                    kernel_binary: record
                        .sizes
                        .kernel_binary
                        .map(|total| ExtendedSizeInfo { total, delta: 0 }),
                    user_app_binary: record
                        .sizes
                        .user_app_binary
                        .map(|total| ExtendedSizeInfo { total, delta: 0 }),
                    total_sram: record
                        .sizes
                        .total_sram
                        .map(|total| ExtendedSizeInfo { total, delta: 0 }),
                },
                is_first: true,
            }
        };
        extended_records.push(ext);
        last_sizes = Some(record.sizes);
    }
    extended_records.reverse();

    // Table header
    md.push_str("| Commit | Author | Title | ROM | Kernel | user-app | SRAM Total |\n");
    md.push_str("|--------|--------|-------|-----|--------|----------|------------|\n");

    for record in &extended_records {
        let commit_short = &record.commit.id[..8.min(record.commit.id.len())];
        let author = name_only(&record.commit.author);
        let mut title = record.commit.title.lines().next().unwrap_or("").to_string();
        title.truncate(50);

        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            commit_short,
            author,
            title,
            format_size_with_delta(&record.sizes.rom_binary),
            format_size_with_delta(&record.sizes.kernel_binary),
            format_size_with_delta(&record.sizes.user_app_binary),
            format_size_with_delta(&record.sizes.total_sram),
        ));
    }

    md.push_str("\n## Legend\n\n");
    md.push_str("- 🟥 Size increased\n");
    md.push_str("- 🟩 Size decreased\n");
    md.push_str("- All sizes in bytes\n");
    md.push_str(&format!("\n## Notes\n\n"));
    md.push_str("- **ROM**: MCU ROM binary size\n");
    md.push_str("- **Kernel**: Runtime kernel ELF loadable segment size\n");
    md.push_str(
        "- **user-app**: User application binary size (with test-pldm-fw-update feature)\n",
    );
    md.push_str(&format!("- **SRAM Total**: Kernel + user-app + kernel stack ({} bytes) + user-app RAM allocation ({} bytes)\n", 
        format_size(KERNEL_STACK_SIZE), format_size(USER_APP_MIN_RAM)));

    md
}

fn format_size_with_delta(info: &Option<ExtendedSizeInfo>) -> String {
    match info {
        Some(info) => {
            let delta_str = match info.delta.cmp(&0) {
                Ordering::Greater => format!(" 🟥+{}", format_size(info.delta as u64)),
                Ordering::Less => format!(" 🟩{}", info.delta),
                Ordering::Equal => String::new(),
            };
            format!("{}{}", format_size(info.total), delta_str)
        }
        None => "build error".to_string(),
    }
}

fn name_only(val: &str) -> &str {
    if let Some((name, _)) = val.split_once('<') {
        name.trim()
    } else {
        val
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct ExtendedSizeInfo {
    total: u64,
    delta: i64,
}

impl ExtendedSizeInfo {
    fn from_change(prev: Option<u64>, current: Option<u64>) -> Option<Self> {
        let prev = prev.unwrap_or(0);
        current.map(|current| Self {
            total: current,
            delta: current.wrapping_sub(prev) as i64,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct ExtendedSizes {
    rom_binary: Option<ExtendedSizeInfo>,
    kernel_binary: Option<ExtendedSizeInfo>,
    user_app_binary: Option<ExtendedSizeInfo>,
    total_sram: Option<ExtendedSizeInfo>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct ExtendedRecord {
    commit: CommitInfo,
    sizes: ExtendedSizes,
    #[allow(dead_code)]
    is_first: bool,
}
