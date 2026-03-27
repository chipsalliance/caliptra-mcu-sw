// Licensed under the Apache-2.0 license

//! Test ROM build functions.
//!
//! This module provides functions for building MCU and Caliptra test ROMs,
//! including feature-specific ROM variants.

use anyhow::Result;
use std::path::PathBuf;

use crate::firmware;
use crate::Platform;
use crate::TARGET;

cfg_if::cfg_if! {
    if #[cfg(feature = "parallel-build")] {
        use rayon::prelude::*;
        fn maybe_into_par_iter<T: Send + 'static>(v: Vec<T>) -> impl ParallelIterator<Item = T> { v.into_par_iter() }
        fn maybe_par_iter<'a, T: Sync + 'a>(slice: &'a [T]) -> impl ParallelIterator<Item = &'a T> { slice.par_iter() }
    } else {
        fn maybe_into_par_iter<T: 'static>(v: Vec<T>) -> impl Iterator<Item = T> { v.into_iter() }
        fn maybe_par_iter<'a, T: 'a>(slice: &'a [T]) -> impl Iterator<Item = &'a T> { slice.iter() }
    }
}

/// Build all registered MCU test ROMs.
///
/// Iterates over `firmware::REGISTERED_FW` and builds a test ROM for each.
/// Supports parallel builds when the `parallel-build` feature is enabled.
///
/// # Arguments
///
/// - `platform`: Target platform (Emulator or Fpga).
///
/// # Returns
///
/// - `Ok(Vec<(PathBuf, String)>)`: List of (path, filename) pairs for built ROMs.
/// - `Err(anyhow::Error)`: If any ROM build fails.
pub fn build_mcu_test_roms(platform: Platform) -> Result<Vec<(PathBuf, String)>> {
    let test_roms: Result<Vec<(PathBuf, String)>> =
        maybe_into_par_iter(firmware::REGISTERED_FW.to_vec())
            .map(|fwid| {
                let target_dir = if cfg!(feature = "parallel-build") {
                    Some(
                        crate::target_dir()
                            .join(format!("target-rom-{}-{}", fwid.crate_name, fwid.bin_name)),
                    )
                } else {
                    None
                };
                let bin_path = PathBuf::from(crate::test_rom_build(platform, fwid, target_dir)?);
                let filename = bin_path.file_name().unwrap().to_str().unwrap().to_string();
                Ok((bin_path, filename))
            })
            .collect();

    test_roms
}

/// Build all registered Caliptra test ROMs.
///
/// Iterates over `firmware::CPTRA_REGISTERED_FW` and builds a test ROM for each.
/// Supports parallel builds when the `parallel-build` feature is enabled.
///
/// # Arguments
///
/// - `_platform`: Target platform (currently unused, for consistency).
///
/// # Returns
///
/// - `Ok(Vec<(PathBuf, String)>)`: List of (path, filename) pairs for built ROMs.
/// - `Err(anyhow::Error)`: If any ROM build fails.
pub fn build_caliptra_test_roms(_platform: Platform) -> Result<Vec<(PathBuf, String)>> {
    let cptra_test_roms: Result<Vec<(PathBuf, String)>> =
        maybe_into_par_iter(firmware::CPTRA_REGISTERED_FW.to_vec())
            .map(|fwid| {
                let filename = format!("cptra-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
                let target_dir = if cfg!(feature = "parallel-build") {
                    crate::target_dir().join(format!("target-cptra-rom-{}", filename))
                } else {
                    crate::target_dir()
                };
                let release_dir = target_dir.join(TARGET).join("release");

                std::fs::create_dir_all(&release_dir)?;
                let bin_path = release_dir.join(&filename);
                let rom_bytes = caliptra_builder::build_firmware_rom(fwid)?;
                std::fs::write(&bin_path, rom_bytes)?;
                Ok((bin_path, filename))
            })
            .collect();

    cptra_test_roms
}

/// Build all test ROMs (MCU + Caliptra).
///
/// Combines the results of `build_mcu_test_roms` and `build_caliptra_test_roms`.
///
/// # Arguments
///
/// - `platform`: Target platform (Emulator or Fpga).
///
/// # Returns
///
/// - `Ok(Vec<(PathBuf, String)>)`: Combined list of all test ROM (path, filename) pairs.
/// - `Err(anyhow::Error)`: If any ROM build fails.
pub fn build_all_test_roms(platform: Platform) -> Result<Vec<(PathBuf, String)>> {
    let mut test_roms = build_mcu_test_roms(platform)?;
    test_roms.extend(build_caliptra_test_roms(platform)?);
    Ok(test_roms)
}

/// Build feature-specific MCU ROMs.
///
/// Attempts to build a ROM with each feature flag. If a feature is not
/// supported by the ROM crate, it is skipped (tests will fall back to
/// the generic MCU ROM).
///
/// # Arguments
///
/// - `platform`: Target platform (Emulator or Fpga).
/// - `features`: List of feature flags to build ROMs for.
///
/// # Returns
///
/// - `Ok(Vec<(PathBuf, String)>)`: List of successfully built (path, filename) pairs.
/// - `Err(anyhow::Error)`: If a critical error occurs (not feature-not-supported).
pub fn build_feature_roms(platform: Platform, features: &[&str]) -> Result<Vec<(PathBuf, String)>> {
    let feature_roms: Result<Vec<(PathBuf, String)>> = maybe_par_iter(features)
        .filter_map(|feature| {
            let target_dir = if cfg!(feature = "parallel-build") {
                Some(crate::target_dir().join(format!("target-feature-rom-{}", feature)))
            } else {
                None
            };
            match crate::rom_build(platform, Some(feature.to_string()), target_dir) {
                Ok(rom_path) => {
                    let rom_name = format!("mcu-test-rom-feature-{}.bin", feature);
                    println!("Built feature ROM: {rom_path:?} -> {}", rom_name);
                    Some(Ok((rom_path, rom_name)))
                }
                Err(e) => {
                    println!(
                        "Skipping feature ROM for {}: {} (will use generic ROM)",
                        feature, e
                    );
                    None
                }
            }
        })
        .collect();

    feature_roms
}
