// Licensed under the Apache-2.0 license

//! Build the Runtime Tock kernel image for VeeR RISC-V.
// Based on the tock board Makefile.common.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

use crate::apps::apps_build_flat_tbf;
use crate::{objcopy, target_binary, target_dir, OBJCOPY_FLAGS, PROJECT_ROOT, SYSROOT, TARGET};
use anyhow::{anyhow, bail, Result};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use mcu_config::McuMemoryMap;
use mcu_config_emulator::flash::LoggingFlashConfig;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

const DEFAULT_PLATFORM: &str = "emulator";
const DEFAULT_RUNTIME_NAME: &str = "runtime.bin";
const INTERRUPT_TABLE_SIZE: usize = 128;
// amount to reserve for data RAM at the end of RAM
const DATA_RAM_SIZE: usize = 152 * 1024;

fn get_apps_memory_offset(elf_file: PathBuf) -> Result<usize> {
    let elf_bytes = std::fs::read(&elf_file)?;
    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(&elf_bytes)?;
    let x = elf_file
        .symbol_table()
        .unwrap()
        .iter()
        .find_map(|(parse_table, string_table)| {
            parse_table
                .iter()
                .find(|p| string_table.get(p.st_name as usize).unwrap_or_default() == "_sappmem")
                .map(|symbol| symbol.st_value as usize)
        });
    x.ok_or(anyhow!("error finding _sappmem symbol"))
}

pub(crate) fn bit_flags(platform: &str) -> &str {
    match platform {
        // TODO: remove this hack when the FPGA has another apeture for MCU SRAM
        "fpga" => "-C target-feature=+relax", // no-op since this is already included
        _ => "-C target-feature=+unaligned-scalar-mem",
    }
}

/// Build the runtime kernel binary without any applications.
/// If parameters are not provided with the offsets and sizes for the kernel and apps, then placeholders
/// will be used.
///
/// Returns the kernel size and the apps memory offset.
#[allow(clippy::too_many_arguments)]
pub fn runtime_build_no_apps_uncached(
    kernel_size: usize,
    apps_offset: usize,
    apps_size: usize,
    features: &[&str],
    output_name: &str,
    platform: &str,
    memory_map: &McuMemoryMap,
    use_dccm_for_stack: bool,
    dccm_offset: Option<u32>,
    dccm_size: Option<u32>,
    log_flash_config: Option<&LoggingFlashConfig>,
    mcu_image_header: Option<&[u8]>,
) -> Result<(usize, usize)> {
    let tock_dir = &PROJECT_ROOT
        .join("platforms")
        .join(platform)
        .join("runtime");
    let sysr = SYSROOT.clone();
    let ld_file_path = tock_dir.join("layout.ld");

    let dccm_offset = dccm_offset.unwrap_or(memory_map.dccm_offset) as usize;
    let dccm_size = dccm_size.unwrap_or(memory_map.dccm_size) as usize;

    let (ram_start, ram_size) = if use_dccm_for_stack {
        let ram_size = dccm_size - INTERRUPT_TABLE_SIZE;
        assert!(
            DATA_RAM_SIZE <= ram_size,
            "DCCM size is not large enough for data RAM"
        );
        (dccm_offset, ram_size)
    } else {
        let ram_start =
            memory_map.sram_offset as usize + memory_map.sram_size as usize - DATA_RAM_SIZE;
        assert!(
            ram_start >= apps_offset + apps_size,
            "RAM must be after apps ram_start {:x} apps_offset {:x} apps_size {:x}",
            ram_start,
            apps_offset,
            apps_size
        );
        (ram_start, DATA_RAM_SIZE)
    };
    let mcu_image_header_size = mcu_image_header.map_or(0, |h| h.len());

    // TODO: print data usage after build from ELF file

    let ld_string = runtime_ld_script(
        memory_map,
        memory_map.sram_offset + mcu_image_header_size as u32,
        kernel_size as u32,
        apps_offset as u32,
        apps_size as u32,
        ram_start as u32,
        ram_size as u32,
        dccm_offset as u32,
        dccm_size as u32,
        log_flash_config,
    )?;

    std::fs::write(&ld_file_path, ld_string)?;

    // The following flags should only be passed to the board's binary crate, but
    // not to any of its dependencies (the kernel, capsules, chips, etc.). The
    // dependencies wouldn't use it, but because the link path is different for each
    // board, Cargo wouldn't be able to cache builds of the dependencies.
    //
    // Indeed, as far as Cargo is concerned, building the kernel with
    // `-C link-arg=-L/tock/boards/imix` is different than building the kernel with
    // `-C link-arg=-L/tock/boards/hail`, so Cargo would have to rebuild the kernel
    // for each board instead of caching it per board (even if in reality the same
    // kernel is built because the link-arg isn't used by the kernel).
    let rustc_flags_for_bin = format!(
        "-C link-arg=-T{} -C link-arg=-L{}/runtime",
        ld_file_path.display(),
        sysr
    );

    // Validate that rustup is new enough.
    let minimum_rustup_version = semver::Version::parse("1.23.0").unwrap();
    let rustup_version = semver::Version::parse(
        String::from_utf8(Command::new("rustup").arg("--version").output()?.stdout)?
            .split(" ")
            .nth(1)
            .unwrap_or(""),
    )?;
    if rustup_version < minimum_rustup_version {
        println!("WARNING: Required tool `rustup` is out-of-date. Attempting to update.");
        if !Command::new("rustup").arg("update").status()?.success() {
            bail!("Failed to update rustup. Please update manually with `rustup update`.");
        }
    }

    // Verify that various required Rust components are installed. All of these steps
    // only have to be done once per Rust version, but will take some time when
    // compiling for the first time.
    if !String::from_utf8(
        Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output()?
            .stdout,
    )?
    .split('\n')
    .any(|line| line.contains(TARGET))
    {
        println!("WARNING: Request to compile for a missing TARGET, will install in 5s");
        std::thread::sleep(std::time::Duration::from_secs(5));
        if !Command::new("rustup")
            .arg("target")
            .arg("add")
            .arg(TARGET)
            .status()?
            .success()
        {
            bail!(format!("Failed to install target {}", TARGET));
        }
    }

    let objcopy = objcopy()?;
    // we delete the .attributes because we don't use host tools for development, and it causes padding
    let objcopy_flags_kernel = format!(
        "{} --remove-section .apps --remove-section .attributes",
        OBJCOPY_FLAGS
    );

    let bin = format!("mcu-runtime-{}", platform);
    let cargo_flags_tock = [
        "--verbose".into(),
        format!("--target={}", TARGET),
        format!("--package {}", bin),
    ]
    .join(" ");

    let features_str = features.join(",");
    let features = if features.is_empty() {
        vec![]
    } else {
        vec!["--features", features_str.as_str()]
    };

    let mut cmd = Command::new("cargo");
    let cmd = cmd
        .arg("rustc")
        .args(cargo_flags_tock.split(' '))
        .arg("--bin")
        .arg(&bin)
        .arg("--release")
        .args(features)
        .arg("--")
        .args(bit_flags(platform).split(' '))
        .args(rustc_flags_for_bin.split(' '))
        .current_dir(tock_dir);

    println!("Executing {:?}", cmd);
    if !cmd.status()?.success() {
        bail!("cargo rustc failed to build runtime");
    }

    let mut cmd = Command::new(&objcopy);
    let cmd = cmd
        .arg("--output-target=binary")
        .args(objcopy_flags_kernel.split(' '))
        .arg(target_binary(&bin))
        .arg(target_binary(output_name));
    println!("Executing {:?}", cmd);
    if !cmd.status()?.success() {
        bail!("objcopy failed to build runtime");
    }

    let kernel_size = std::fs::metadata(target_binary(output_name)).unwrap().len() as usize;

    get_apps_memory_offset(target_binary(&bin)).map(|apps_offset| (kernel_size, apps_offset))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CachedValues {
    kernel_size: usize,
    apps_offset: usize,
    apps_size: usize,
}

impl Default for CachedValues {
    fn default() -> Self {
        CachedValues {
            kernel_size: 140 * 1024,
            apps_offset: (mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_offset + 140 * 1024)
                as usize,
            apps_size: 80 * 1024,
        }
    }
}

fn read_cached_values(platform: &str) -> CachedValues {
    let cache_file = target_dir().join(format!("cached-values-{}.json", platform));
    if let Ok(data) = std::fs::read_to_string(&cache_file) {
        if let Ok(values) = serde_json::from_str::<CachedValues>(&data) {
            return values;
        }
    }
    CachedValues::default()
}

fn write_cached_values(platform: &str, values: &CachedValues) {
    let cache_file = target_dir().join(format!("cached-values-{}.json", platform));
    match serde_json::to_string(values) {
        Ok(data) => {
            if let Err(err) = std::fs::write(cache_file, data) {
                println!(
                    "Error writing cached values for platform {}; igoring: {}",
                    platform, err
                );
            }
        }
        Err(err) => println!(
            "Failed to write cached values for platform {}; ignoring: {}",
            platform, err
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_build_with_apps_cached(
    features: &[&str],
    output_name: Option<&str>,
    example_app: bool,
    platform: Option<&str>,
    memory_map: Option<&McuMemoryMap>,
    use_dccm_for_stack: bool,
    dccm_offset: Option<u32>,
    dccm_size: Option<u32>,
    log_flash_config: Option<&LoggingFlashConfig>,
    mcu_image_header: Option<&[u8]>,
) -> Result<String> {
    let memory_map = memory_map.unwrap_or(&mcu_config_emulator::EMULATOR_MEMORY_MAP);
    let mut app_offset = memory_map.sram_offset as usize;
    let output_name = output_name.unwrap_or(DEFAULT_RUNTIME_NAME);
    let runtime_bin = target_binary(output_name);

    let platform = platform.unwrap_or(DEFAULT_PLATFORM);
    let mut cached_values = read_cached_values(platform);
    println!(
        "Read cached values for platform {}: {:?}",
        platform, cached_values
    );

    let log_flash_config = if platform == "emulator" {
        Some(&mcu_config_emulator::flash::LOGGING_FLASH_CONFIG)
    } else {
        None
    };

    // build once to get the size of the runtime binary without apps
    let (kernel_size, apps_memory_offset) = match runtime_build_no_apps_uncached(
        cached_values.kernel_size,
        cached_values.apps_offset,
        cached_values.apps_size,
        features,
        output_name,
        platform,
        memory_map,
        use_dccm_for_stack,
        dccm_offset,
        dccm_size,
        log_flash_config,
        mcu_image_header,
    ) {
        Ok((kernel_size, apps_memory_offset)) => (kernel_size, apps_memory_offset),
        Err(_) => {
            // if it fails, bust the cache and rebuild with default values
            cached_values = CachedValues::default();
            println!(
        "Build failed with cached values; busting the cache and using defaults for platform {}: {:?}",
        platform, cached_values
        );

            runtime_build_no_apps_uncached(
                cached_values.kernel_size,
                cached_values.apps_offset,
                cached_values.apps_size,
                features,
                output_name,
                platform,
                memory_map,
                use_dccm_for_stack,
                dccm_offset,
                dccm_size,
                log_flash_config,
                mcu_image_header,
            )?
        }
    };

    let mcu_header_size = mcu_image_header.map_or(0, |h| h.len());
    let runtime_bin_size = std::fs::metadata(&runtime_bin)?.len() as usize + mcu_header_size;
    app_offset += runtime_bin_size;
    let runtime_end_offset = app_offset;

    // and align to 4096 bytes (needed for rust-lld)
    let apps_offset = runtime_end_offset.next_multiple_of(4096);
    let padding = apps_offset - runtime_end_offset;

    // build the apps with the data memory at some incorrect offset
    let apps_bin = apps_build_flat_tbf(
        platform,
        apps_offset,
        apps_memory_offset,
        features,
        example_app,
    )?;
    let apps_bin_len = apps_bin.len();
    println!("Apps built: {} bytes", apps_bin_len);

    if kernel_size != cached_values.kernel_size
        || apps_offset != cached_values.apps_offset
        || apps_bin_len != cached_values.apps_size
    {
        println!("Rebuilding kernel with correct offsets and sizes");
        // re-link and place the apps and data RAM after the runtime binary
        let (kernel_size2, new_apps_memory_offset) = runtime_build_no_apps_uncached(
            kernel_size,
            apps_offset,
            apps_bin_len,
            features,
            output_name,
            platform,
            memory_map,
            use_dccm_for_stack,
            dccm_offset,
            dccm_size,
            log_flash_config,
            mcu_image_header,
        )?;

        assert_eq!(
            kernel_size, kernel_size2,
            "Kernel size changed between runs"
        );
        assert_eq!(
            apps_memory_offset, new_apps_memory_offset,
            "Apps memory offset changed between runs"
        );
    }

    if apps_offset != cached_values.apps_offset {
        println!("Rebuilding apps with correct offsets");

        // re-link the applications with the correct data memory offsets
        let apps_bin = apps_build_flat_tbf(
            platform,
            apps_offset,
            apps_memory_offset,
            features,
            example_app,
        )?;
        assert_eq!(
            apps_bin_len,
            apps_bin.len(),
            "Applications sizes changed between runs"
        );
        println!("Apps built: {} bytes", apps_bin.len());
    }

    println!("Apps data memory offset is {:x}", apps_memory_offset);

    let mut bin = Vec::new();

    if let Some(mcu_image_header) = mcu_image_header {
        bin.extend_from_slice(mcu_image_header);
    };
    bin.extend(std::fs::read(&runtime_bin)?);
    let kernel_size = bin.len();
    println!("Kernel binary built: {} bytes", kernel_size);

    bin.extend_from_slice(vec![0; padding].as_slice());
    bin.extend_from_slice(&apps_bin);
    // Ensure that runtime binary is a multiple of 256 bytes.
    // This is needed to load into the recovery interface efficiently.
    if bin.len() % 256 != 0 {
        let padding = 256 - (bin.len() % 256);
        bin.extend_from_slice(vec![0; padding].as_slice());
    }
    std::fs::write(&runtime_bin, &bin)?;

    println!("Kernel binary size: {} bytes", kernel_size);
    println!("Total runtime binary: {} bytes", bin.len());
    println!("Runtime binary is available at {:?}", &runtime_bin);

    // update the cache
    let cached_values = CachedValues {
        kernel_size,
        apps_offset,
        apps_size: apps_bin_len,
    };
    println!(
        "Updating cached values for platform {}: {:?}",
        platform, cached_values
    );
    write_cached_values(platform, &cached_values);

    Ok(runtime_bin.to_string_lossy().to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_ld_script(
    memory_map: &McuMemoryMap,
    runtime_offset: u32,
    runtime_size: u32,
    apps_offset: u32,
    apps_size: u32,
    data_ram_offset: u32,
    data_ram_size: u32,
    dccm_offset: u32,
    dccm_size: u32,
    log_flash_config: Option<&LoggingFlashConfig>,
) -> Result<String> {
    let mut map = memory_map.hash_map();
    map.insert("DCCM_OFFSET".to_string(), format!("0x{:x}", dccm_offset));
    map.insert("DCCM_SIZE".to_string(), format!("0x{:x}", dccm_size));
    map.insert(
        "RUNTIME_OFFSET".to_string(),
        format!("0x{:x}", runtime_offset),
    );
    map.insert("RUNTIME_SIZE".to_string(), format!("0x{:x}", runtime_size));
    map.insert("APPS_OFFSET".to_string(), format!("0x{:x}", apps_offset));
    map.insert("APPS_SIZE".to_string(), format!("0x{:x}", apps_size));
    map.insert(
        "DATA_RAM_OFFSET".to_string(),
        format!("0x{:x}", data_ram_offset),
    );
    map.insert(
        "DATA_RAM_SIZE".to_string(),
        format!("0x{:x}", data_ram_size),
    );

    if let Some(cfg) = log_flash_config {
        map.insert(
            "FLASH_OFFSET".to_string(),
            format!("0x{:x}", cfg.logging_flash_offset),
        );
        map.insert(
            "FLASH_SIZE".to_string(),
            format!("0x{:x}", cfg.logging_flash_size),
        );
        map.insert(
            "PAGE_SIZE".to_string(),
            format!("PAGE_SIZE = {};", cfg.page_size),
        );
    } else {
        map.insert("FLASH_OFFSET".to_string(), "0x0".to_string());
        map.insert("FLASH_SIZE".to_string(), "0x0".to_string());
        map.insert("PAGE_SIZE".to_string(), "".to_string());
    }

    Ok(subst::substitute(RUNTIME_LD_TEMPLATE, &map)?)
}

const RUNTIME_LD_TEMPLATE: &str = r#"
/* Licensed under the Apache-2.0 license. */

/* Based on the Tock board layouts, which are: */
/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2023.                                  */

MEMORY
{
    rom (rx)  : ORIGIN = $RUNTIME_OFFSET, LENGTH = $RUNTIME_SIZE
    prog (rx) : ORIGIN = $APPS_OFFSET, LENGTH = $APPS_SIZE
    ram (rwx) : ORIGIN = $DATA_RAM_OFFSET, LENGTH = $DATA_RAM_SIZE
    dccm (rw) : ORIGIN = $DCCM_OFFSET, LENGTH = $DCCM_SIZE
    flash (r) : ORIGIN = $FLASH_OFFSET, LENGTH = $FLASH_SIZE
}

$PAGE_SIZE

INCLUDE platforms/emulator/runtime/kernel_layout.ld
"#;
