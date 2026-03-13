// Licensed under the Apache-2.0 license.

use std::env;
use std::path::PathBuf;

#[cfg(feature = "fpga_realtime")]
mod platform {
    pub use mcu_config_fpga::FPGA_MEMORY_MAP as MEMORY_MAP;
    pub const LD_FILE: &str = "fpga-rom-layout.ld";
}
#[cfg(not(feature = "fpga_realtime"))]
mod platform {
    pub use mcu_config_emulator::EMULATOR_MEMORY_MAP as MEMORY_MAP;
    pub const LD_FILE: &str = "emulator-rom-layout.ld";
}

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let out_dir = env::var("OUT_DIR").unwrap_or_default();
    if arch == "riscv32" {
        let ld_file = PathBuf::from(out_dir).join(platform::LD_FILE);
        let current_ld = std::fs::read_to_string(&ld_file).unwrap_or_default();
        let ld_script = mcu_builder::rom_ld_script(&platform::MEMORY_MAP);
        if ld_script != current_ld {
            std::fs::write(&ld_file, ld_script).unwrap();
        }

        println!("cargo:rustc-link-arg=-T{}", ld_file.display());
        println!("cargo:rerun-if-changed={}", ld_file.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
