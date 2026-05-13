// Licensed under the Apache-2.0 license

use std::{path::PathBuf, process::Command};

use anyhow::{bail, Result};

use crate::objcopy;
use crate::utils::manifest_file;
use crate::{PROJECT_ROOT, TARGET};
use caliptra_builder::FwId;
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use mcu_config::McuMemoryMap;
use mcu_firmware_bundler::args::{BuildArgs, Commands, Common, LdArgs};

pub fn rom_build(platform: Option<String>, features: Option<String>) -> Result<PathBuf> {
    let feature_suffix = match &features {
        Some(f) => format!("-{f}"),
        None => String::new(),
    };

    let target_name = format!(
        "mcu-rom-{}",
        platform.clone().unwrap_or_else(|| "emulator".to_string())
    );
    let rom = format!("{target_name}{feature_suffix}");
    let manifest = manifest_file(platform.as_deref(), false)?;
    let common = Common {
        manifest,
        ..Default::default()
    };
    let rom_size = rom_size_for_platform(platform.as_deref().unwrap_or("emulator"));
    let rom_binary = common.release_dir().map(|t| t.join(format!("{rom}.bin")))?;
    let build_cmd = Commands::Build {
        common,
        ld: LdArgs::default(),
        build: BuildArgs {
            rom_features: features.clone(),
            ..Default::default()
        },
        target: Some(target_name.clone()),
    };

    mcu_firmware_bundler::execute(build_cmd)?;
    std::fs::rename(
        rom_binary.with_file_name(format!("{target_name}.bin")),
        &rom_binary,
    )?;
    assert!(rom_binary.exists(), "{rom_binary:?} does not exist");
    append_rom_digest(&rom_binary, rom_size)?;
    Ok(rom_binary)
}

/// Pad the ROM binary to its full size and append a SHA384 digest of its contents to the end.
pub fn append_rom_digest(binary: &PathBuf, rom_size: usize) -> Result<()> {
    let mut data = std::fs::read(binary)?;
    const DIGEST_SIZE: usize = 48;
    let digest_offset = rom_size - DIGEST_SIZE;
    data.resize(rom_size, 0);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&data[0..digest_offset])?);
    data[digest_offset..].copy_from_slice(&digest);
    std::fs::write(binary, data)?;
    Ok(())
}

pub fn test_rom_build(platform: Option<&str>, fwid: &FwId) -> Result<String> {
    let platform = platform.unwrap_or("emulator");

    let platform_bin = format!("mcu-test-rom-{}-{}.bin", fwid.crate_name, fwid.bin_name);
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "build",
        "-p",
        fwid.crate_name,
        "--release",
        "--target",
        TARGET,
    ]);

    let mut features = fwid.features.to_vec();
    if !features.contains(&"riscv") {
        features.push("riscv");
    }
    if platform != "emulator" {
        features.push("fpga_realtime");
    }
    cmd.args(["--features", &features.join(",")]);

    println!("Executing: {cmd:?}");
    let status = cmd.status()?;
    if !status.success() {
        bail!("build ROM binary failed");
    }
    let rom_elf = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(fwid.bin_name);

    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(&platform_bin);

    let objcopy = objcopy()?;
    let objcopy_flags = "--strip-sections --strip-all";
    let mut objcopy_cmd = Command::new(objcopy);
    objcopy_cmd
        .arg("--output-target=binary")
        .args(objcopy_flags.split(' '))
        .arg(&rom_elf)
        .arg(&rom_binary);
    println!("Executing {:?}", &objcopy_cmd);
    if !objcopy_cmd.status()?.success() {
        bail!("objcopy failed to build ROM");
    }
    println!(
        "ROM binary ({}) is at {:?} ({} bytes)",
        platform,
        &rom_binary,
        std::fs::metadata(&rom_binary)?.len()
    );
    let rom_size = rom_size_for_platform(platform);
    append_rom_digest(&rom_binary, rom_size)?;
    Ok(rom_binary.to_string_lossy().to_string())
}

pub fn rom_size_for_platform(platform: &str) -> usize {
    match platform {
        "fpga" => mcu_config_fpga::FPGA_MEMORY_MAP.rom_size as usize,
        _ => mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size as usize,
    }
}

pub fn rom_ld_script(memory_map: &McuMemoryMap) -> String {
    subst::substitute(ROM_LD_TEMPLATE, &memory_map.hash_map()).unwrap()
}

const ROM_LD_TEMPLATE: &str = r#"
/* Licensed under the Apache-2.0 license. */

ENTRY(_start)
OUTPUT_ARCH( "riscv" )

MEMORY
{
  ROM   (rx) : ORIGIN = $ROM_OFFSET, LENGTH = $ROM_SIZE
  RAM  (rwx) : ORIGIN = $DCCM_OFFSET, LENGTH = $DCCM_SIZE /* dedicated SRAM for the ROM stack */
  HANDOFF (rw) : ORIGIN = $HANDOFF_OFFSET, LENGTH = $HANDOFF_SIZE
}

SECTIONS
{
    .text :
    {
        *(.text.init )
        *(.text*)
        *(.rodata*)
    } > ROM

    ROM_DATA = .;

    /DISCARD/ :
    {
        *(.eh_frame*)
    }

    .data : AT(ROM_DATA)
    {
        . = ALIGN(4);
        *(.data*);
        *(.sdata*);
        . = ALIGN(4);
        PROVIDE( GLOBAL_POINTER = . + 0x800 );
        . = ALIGN(4);
    } > RAM

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
    } > RAM

    .stack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + STACK_SIZE;
        . = ALIGN(4);
        PROVIDE(STACK_START = . );
    } > RAM

    .estack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + ESTACK_SIZE;
        . = ALIGN(4);
        PROVIDE(ESTACK_START = . );
    }

    /* We reserve 1 KB at the end of DCCM for the handoff table.
       This must be 1KB aligned because the runtime requires DCCM regions
       to be 1KB aligned for MEIVT (Machine External Interrupt Vector Table). */
    .handoff (NOLOAD) :
    {
        KEEP(*(.handoff))
    } > HANDOFF

    _end = . ;

    /DISCARD/ :
    {
        *(.eh_frame*)
    }
}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
STACK_SIZE = $ROM_STACK_SIZE;
STACK_TOP = ORIGIN(RAM) + LENGTH(RAM);
STACK_ORIGIN = STACK_TOP - STACK_SIZE;
ESTACK_SIZE = $ROM_ESTACK_SIZE;

"#;
