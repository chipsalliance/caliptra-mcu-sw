// Licensed under the Apache-2.0 license.

use mcu_config_emulator::EMULATOR_MEMORY_MAP;
use std::env;
use std::path::PathBuf;

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let out_dir = env::var("OUT_DIR").unwrap_or_default();
    if arch == "riscv32" {
        let ld_file = PathBuf::from(out_dir).join("emulator-rom-layout.ld");
        let current_ld = std::fs::read_to_string(&ld_file).unwrap_or_default();
        let ld_script = mcu_builder::rom_ld_script(&EMULATOR_MEMORY_MAP);
        if ld_script != current_ld {
            std::fs::write(&ld_file, ld_script).unwrap();
        }

        println!("cargo:rustc-link-arg=-T{}", ld_file.display());
        println!("cargo:rerun-if-changed={}", ld_file.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
