// Licensed under the Apache-2.0 license.

use network_config::DEFAULT_NETWORK_MEMORY_MAP;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let out_dir = env::var("OUT_DIR").unwrap_or_default();

    if arch == "riscv32" {
        // Generate linker script for network coprocessor memory layout
        let ld_script = generate_linker_script();
        let ld_file = PathBuf::from(&out_dir).join("network-rom-layout.ld");

        let current_ld = fs::read_to_string(&ld_file).unwrap_or_default();
        if ld_script != current_ld {
            fs::write(&ld_file, &ld_script).unwrap();
        }

        println!("cargo:rustc-link-arg=-T{}", ld_file.display());
        println!("cargo:rerun-if-changed={}", ld_file.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}

fn generate_linker_script() -> String {
    let map = &DEFAULT_NETWORK_MEMORY_MAP;
    let mrac_value = map.compute_mrac();

    format!(
        r#"
/* Licensed under the Apache-2.0 license. */
/* Network Coprocessor Linker Script - Generated from network-config */

ENTRY(_start)
OUTPUT_ARCH( "riscv" )

MEMORY
{{
  ROM   (rx) : ORIGIN = 0x{rom_offset:08x}, LENGTH = 0x{rom_size:x}
  ICCM (rwx) : ORIGIN = 0x{iccm_offset:08x}, LENGTH = 0x{iccm_size:x}
  DCCM (rw)  : ORIGIN = 0x{dccm_offset:08x}, LENGTH = 0x{dccm_size:x}
}}

SECTIONS
{{
    .text :
    {{
        *(.text.init )
        *(.text*)
        *(.rodata*)
        *(.srodata*)
    }} > ROM

    ROM_DATA = .;

    .data : AT(ROM_DATA)
    {{
        . = ALIGN(4);
        *(.data*);
        *(.sdata*);
        KEEP(*(.eh_frame))
        . = ALIGN(4);
        PROVIDE( GLOBAL_POINTER = . + 0x800 );
        . = ALIGN(4);
    }} > DCCM

    .bss (NOLOAD) :
    {{
        . = ALIGN(4);
        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
    }} > DCCM

    .stack (NOLOAD):
    {{
        . = ALIGN(4);
        . = . + STACK_SIZE;
        . = ALIGN(4);
        PROVIDE(STACK_START = . );
    }} > DCCM

    _end = . ;
}}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
STACK_SIZE = 0x{stack_size:x};
STACK_TOP = ORIGIN(DCCM) + LENGTH(DCCM);
STACK_ORIGIN = STACK_TOP - STACK_SIZE;

/* MRAC value computed from memory map */
MRAC_VALUE = 0x{mrac_value:08x};

"#,
        rom_offset = map.rom_offset,
        rom_size = map.rom_size,
        iccm_offset = map.iccm_offset,
        iccm_size = map.iccm_size,
        dccm_offset = map.dccm_offset,
        dccm_size = map.dccm_size,
        stack_size = map.rom_stack_size,
        mrac_value = mrac_value,
    )
}
