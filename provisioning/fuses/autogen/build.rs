// Licensed under the Apache-2.0 license

use std::path::PathBuf;

#[path = "src/lib_generator.rs"]
mod lib_generator;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(manifest_dir).join("../../..");

    let otp_mmap = project_root.join(lib_generator::OTP_CTRL_MMAP_DEFAULT_PATH);
    let otp_values = project_root.join(lib_generator::FUSE_VALUES_DEFAULT_PATH);

    let dest_path = project_root.join(lib_generator::FUSE_LIB_DEFAULT_PATH);

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    lib_generator::generate_fuse_values_file(&otp_mmap, &otp_values, &dest_path).unwrap();

    println!("cargo:rerun-if-changed={}", otp_mmap.display());
    println!("cargo:rerun-if-changed={}", otp_values.display());
}
