// Licensed under the Apache-2.0 license

//! Build the Runtime Tock kernel image for VeeR RISC-V.
// Based on the tock board Makefile.common.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use crate::apps::apps_build_flat_tbf;
use crate::{objcopy, target_binary, OBJCOPY_FLAGS, PROJECT_ROOT, SYSROOT, TARGET};
use anyhow::{anyhow, bail, Result};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use emulator_consts::{RAM_ORG, RAM_SIZE};
use mcu_config::McuMemoryMap;
use std::path::PathBuf;
use std::process::Command;

const DEFAULT_RUNTIME_NAME: &str = "runtime.bin";
const INTERRUPT_TABLE_SIZE: usize = 128;
// amount to reserve for data RAM at the end of RAM
const DATA_RAM_SIZE: usize = 128 * 1024;

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

/// Build the runtime kernel binary without any applications.
/// If parameters are not provided with the offsets and sizes for the kernel and apps, then placeholders
/// will be used.
///
/// Returns the kernel size and the apps memory offset.
pub fn runtime_build_no_apps(
    kernel_size: Option<usize>,
    apps_offset: Option<usize>,
    apps_size: Option<usize>,
    features: &[&str],
    output_name: &str,
    platform: Option<&str>,
    memory_map: Option<&McuMemoryMap>,
) -> Result<(usize, usize)> {
    let platform = platform.unwrap_or("emulator");
    let memory_map = memory_map.unwrap_or(&mcu_config_emulator::EMULATOR_MEMORY_MAP);
    let tock_dir = &PROJECT_ROOT
        .join("platforms")
        .join(platform)
        .join("runtime");
    let sysr = SYSROOT.clone();
    let ld_file_path = tock_dir.join("layout.ld");

    // placeholder values
    let runtime_size = kernel_size.unwrap_or(128 * 1024);
    let apps_offset = apps_offset.unwrap_or(memory_map.sram_offset as usize + 192 * 1024);
    let apps_size = apps_size.unwrap_or(64 * 1024);

    let ram_start = memory_map.sram_offset as usize + RAM_SIZE as usize - DATA_RAM_SIZE;
    assert!(
        ram_start >= apps_offset + apps_size,
        "RAM must be after apps ram_start {:x} apps_offset {:x} apps_size {:x}",
        ram_start,
        apps_offset,
        apps_size
    );

    let ld_string = runtime_ld_script(
        memory_map,
        memory_map.sram_offset + INTERRUPT_TABLE_SIZE as u32,
        runtime_size as u32,
        apps_offset as u32,
        apps_size as u32,
        ram_start as u32,
        DATA_RAM_SIZE as u32,
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

    // Add flags since we are compiling on nightly.
    //
    // - `-Z build-std=core,compiler_builtins`: Build the std library from source
    //   using our optimization settings. This leads to significantly smaller binary
    //   sizes, and makes debugging easier since debug information for the core
    //   library is included in the resulting .elf file. See
    //   https://github.com/tock/tock/pull/2847 for more details.
    // - `optimize_for_size`: Sets a feature flag in the core library that aims to
    //   produce smaller implementations for certain algorithms. See
    //   https://github.com/rust-lang/rust/pull/125011 for more details.
    let bin = format!("mcu-runtime-{}", platform);
    let cargo_flags_tock = [
        "--verbose".into(),
        format!("--target={}", TARGET),
        format!("--package {}", bin),
        "-Z build-std=core,compiler_builtins".into(),
        "-Z build-std-features=core/optimize_for_size".into(),
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

pub fn runtime_build_with_apps(
    features: &[&str],
    output_name: Option<&str>,
    example_app: bool,
    platform: Option<&str>,
    memory_map: Option<&McuMemoryMap>,
) -> Result<String> {
    let mut app_offset = memory_map.map(|m| m.sram_offset).unwrap_or(RAM_ORG) as usize;
    let output_name = output_name.unwrap_or(DEFAULT_RUNTIME_NAME);
    let runtime_bin = target_binary(output_name);

    // build once to get the size of the runtime binary without apps
    let (kernel_size, apps_memory_offset) = runtime_build_no_apps(
        None,
        None,
        None,
        features,
        output_name,
        platform,
        memory_map,
    )?;

    let runtime_bin_size = std::fs::metadata(&runtime_bin)?.len() as usize;
    app_offset += runtime_bin_size;
    let runtime_end_offset = app_offset;

    // ensure that we leave space for the interrupt table
    // and align to 4096 bytes (needed for rust-lld)
    let app_offset = (runtime_end_offset + INTERRUPT_TABLE_SIZE).next_multiple_of(4096);
    let padding = app_offset - runtime_end_offset - INTERRUPT_TABLE_SIZE;

    // build the apps with the data memory at some incorrect offset
    let apps_bin_len =
        apps_build_flat_tbf(app_offset, apps_memory_offset, features, example_app)?.len();
    println!("Apps built: {} bytes", apps_bin_len);

    // re-link and place the apps and data RAM after the runtime binary
    let (kernel_size2, apps_memory_offset) = runtime_build_no_apps(
        Some(kernel_size),
        Some(app_offset),
        Some(apps_bin_len),
        features,
        output_name,
        platform,
        memory_map,
    )?;

    assert_eq!(
        kernel_size, kernel_size2,
        "Kernel size changed between runs"
    );

    // re-link the applications with the correct data memory offsets
    let apps_bin = apps_build_flat_tbf(app_offset, apps_memory_offset, features, example_app)?;
    assert_eq!(
        apps_bin_len,
        apps_bin.len(),
        "Applications sizes changed between runs"
    );

    println!("Apps data memory offset is {:x}", apps_memory_offset);
    println!("Apps built: {} bytes", apps_bin.len());

    let mut bin = std::fs::read(&runtime_bin)?;
    let kernel_size = bin.len();
    println!("Kernel binary built: {} bytes", kernel_size);

    bin.extend_from_slice(vec![0; padding].as_slice());
    bin.extend_from_slice(&apps_bin);
    std::fs::write(&runtime_bin, &bin)?;

    println!("Kernel binary size: {} bytes", kernel_size);
    println!("Total runtime binary: {} bytes", bin.len());
    println!("Runtime binary is available at {:?}", &runtime_bin);

    Ok(runtime_bin.to_string_lossy().to_string())
}

pub fn runtime_ld_script(
    memory_map: &McuMemoryMap,
    runtime_offset: u32,
    runtime_size: u32,
    apps_offset: u32,
    apps_size: u32,
    data_ram_offset: u32,
    data_ram_size: u32,
) -> Result<String> {
    let mut map = memory_map.hash_map();
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
}

INCLUDE platforms/emulator/runtime/kernel_layout.ld
"#;
