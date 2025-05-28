// Licensed under the Apache-2.0 license

use crate::objcopy;
use crate::{PROJECT_ROOT, TARGET};
use anyhow::{bail, Result};
use mcu_config::McuMemoryMap;
use std::process::Command;

pub fn rom_build(platform: Option<&str>, feature: &str) -> Result<String> {
    let platform = platform.unwrap_or("emulator");
    let platform_pkg = format!("mcu-rom-{}", platform);
    let feature_suffix = if feature.is_empty() {
        "".to_string()
    } else {
        format!("-{}", feature)
    };

    let platform_bin = format!("mcu-rom-{}{}.bin", platform, feature_suffix);
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "build",
        "-p",
        &platform_pkg,
        "--release",
        "--target",
        TARGET,
    ]);
    if !feature.is_empty() {
        cmd.args(["--features", feature]);
    }
    let status = cmd.status()?;
    if !status.success() {
        bail!("build ROM binary failed");
    }
    let rom_elf = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(&platform_pkg);

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
    Ok(rom_binary.to_string_lossy().to_string())
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

    .data : AT(ROM_DATA)
    {
        . = ALIGN(4);
        *(.data*);
        *(.sdata*);
        KEEP(*(.eh_frame))
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

    _end = . ;
}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
STACK_SIZE = $ROM_STACK_SIZE;
STACK_TOP = ORIGIN(RAM) + LENGTH(RAM);
STACK_ORIGIN = STACK_TOP - STACK_SIZE;

"#;
