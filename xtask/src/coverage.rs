// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_mcu_builder::{rom_build, PROJECT_ROOT};
use std::process::Command;

pub(crate) fn coverage(analyze_only: bool) -> Result<()> {
    let cov_dir = std::env::var("MCU_COVERAGE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("mcu-coverage"));

    if !analyze_only {
        // Clean previous coverage data
        if cov_dir.exists() {
            std::fs::remove_dir_all(&cov_dir)?;
        }
        std::fs::create_dir_all(&cov_dir)?;
    }

    // Build MCU ROM so we have the binary and ELF for analysis
    let rom_path = rom_build(&caliptra_mcu_builder::CaliptraBuildArgs::default());
    let (rom_path, rom_elf) = match rom_path {
        Ok(p) => {
            let elf = p.with_extension("");
            (Some(p), Some(elf))
        }
        Err(e) => {
            if analyze_only {
                println!("ROM build skipped in analyze-only mode: {}", e);
                (None, None)
            } else {
                return Err(e);
            }
        }
    };

    if !analyze_only {
        // Run tests with coverage collection via env var
        println!("Running tests with coverage collection enabled...");
        let mut cmd = Command::new("cargo");
        cmd.current_dir(PROJECT_ROOT.as_path())
            .env("MCU_COVERAGE_PATH", cov_dir.to_str().unwrap())
            .arg("nextest")
            .arg("run")
            .arg("--workspace")
            .arg("--test-threads=1")
            .arg("--profile=nightly-emulator");

        // Exclude packages that don't have tests or are platform-specific
        for pkg in &[
            "bare-metal-runtime",
            "mcu-rom-emulator",
            "mcu-rom-fpga",
            "mcu-runtime-emulator",
            "mcu-runtime-fpga",
            "emulator",
            "test-hello",
            "user-app",
            "example-app",
            "libtock_unittest",
            "syscalls_tests",
            "mcu-test-fw-exception-handler",
            "mcu-test-fw-hitless-update-flow",
            "mcu-test-fw-lc-ctrl",
            "mcu-test-fw-mailbox-responder",
            "mcu-test-fw-otp-blank-check",
            "mcu-test-fw-sw-digest-lock",
        ] {
            cmd.arg("--exclude").arg(pkg);
        }

        let status = cmd.status()?;
        if !status.success() {
            println!("Warning: some tests failed, but continuing with coverage analysis");
        }
    }

    // Analyze coverage
    println!("Analyzing coverage...");

    let paths = caliptra_mcu_coverage::get_bitvec_paths(cov_dir.to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if paths.is_empty() {
        bail!("No coverage files found in {}", cov_dir.display());
    }

    println!("{} coverage files found", paths.len());

    let cv = caliptra_mcu_coverage::CoverageMap::new(paths);

    // ROM coverage
    if let (Some(ref rom_elf_path), Some(ref rom_bin_path)) = (&rom_elf, &rom_path) {
        if rom_elf_path.exists() {
            let elf_bytes = std::fs::read(rom_elf_path)?;
            let rom_image = std::fs::read(rom_bin_path)?;
            let rom_tag = caliptra_mcu_coverage::get_tag_from_image(&rom_image);

            if let Some(bv) = cv.map.get(&rom_tag) {
                let (load_addr, instr_pcs) =
                    caliptra_mcu_coverage::collect_instr_pcs_from_elf(&elf_bytes)?;
                let (hit, total) =
                    caliptra_mcu_coverage::coverage_from_bitmap(load_addr as usize, bv, &instr_pcs);

                println!("////////////////////////////////////");
                println!("MCU ROM Coverage");
                println!("////////////////////////////////////");
                println!("Instruction count = {}", total);
                println!(
                    "Coverage = {}%",
                    if total > 0 {
                        (100 * hit) as f32 / total as f32
                    } else {
                        0.0
                    }
                );

                let uncovered =
                    caliptra_mcu_coverage::uncovered_functions(load_addr as usize, &elf_bytes, bv)?;
                for f in &uncovered {
                    println!("{}", f);
                }
            } else {
                println!("No coverage data found for MCU ROM (tag={})", rom_tag);
            }
        } else {
            println!("MCU ROM ELF not found at {}", rom_elf_path.display());
        }
    } else {
        println!("MCU ROM build not available, skipping ROM coverage analysis");
    }

    // ICCM/SRAM coverage - report any remaining tags
    for (tag, bv) in &cv.map {
        let rom_tag = rom_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .map(|img| caliptra_mcu_coverage::get_tag_from_image(&img));
        if rom_tag.as_ref() == Some(tag) {
            continue;
        }
        let hit_count = bv.iter().filter(|b| *b).count();
        let total_bits = bv.len();
        println!("////////////////////////////////////");
        println!("ICCM/SRAM Coverage (tag={})", tag);
        println!("////////////////////////////////////");
        println!(
            "Bits set = {} / {} ({:.1}%)",
            hit_count,
            total_bits,
            if total_bits > 0 {
                100.0 * hit_count as f64 / total_bits as f64
            } else {
                0.0
            }
        );
    }

    Ok(())
}
