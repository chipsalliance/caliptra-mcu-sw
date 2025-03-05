// Licensed under the Apache-2.0 license.

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch == "riscv32" {
        println!("cargo:rustc-link-arg=-Tplatforms/emulator/rom/layout.ld");
        println!("cargo:rerun-if-changed=layout.ld");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
