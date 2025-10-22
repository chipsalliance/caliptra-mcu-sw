/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=../app_layout.ld");
    println!("cargo:rerun-if-changed=../user-app-layout.ld");

    write_fw_components_config();
}

/// Copy the generated `soc_env_config.rs` into `OUT_DIR` or emit a stub if it is missing.
/// In strict mode (`FW_COMPONENTS_STRICT` set) absence of the source file causes a panic.
fn write_fw_components_config() {
    // Locate workspace root by walking up the directory tree.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // Ancestors: user -> apps -> userspace -> runtime -> emulator -> platforms -> <root>
    let workspace_root = manifest_dir
        .ancestors()
        .nth(6)
        .expect("Unable to determine workspace root from user-app path");

    let src_file = workspace_root.join("target/generated/soc_env_config.rs");
    println!("cargo:rerun-if-changed={}", src_file.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::create_dir_all(&out_dir).unwrap();
    let dest = out_dir.join("soc_env_config.rs");

    if !src_file.exists() {
        let strict = env::var("FW_COMPONENTS_STRICT").is_ok();
        if strict {
            panic!(
                "Required generated file '{}' not found (strict mode). Run generation first or unset FW_COMPONENTS_STRICT.",
                src_file.display()
            );
        }
        let stub = r#"// Stub generated because real soc_env_config.rs not found.
pub const VENDOR: &str = "UNKNOWN";
pub const MODEL: &str = "UNKNOWN";
pub const NUM_FW_COMPONENTS: usize = 0;
pub const FW_IDS: [u32; 0] = [];
pub const FW_ID_STRS: [&str; 0] = [];
"#;
        fs::write(&dest, stub).expect("Failed to write stub soc_env_config.rs");
        println!("cargo:warning=soc_env_config.rs missing at {}; emitted stub (set FW_COMPONENTS_STRICT=1 to make this a build error)", src_file.display());
    } else {
        fs::copy(&src_file, &dest).expect("Failed to copy soc_env_config.rs into OUT_DIR");
    }
}
