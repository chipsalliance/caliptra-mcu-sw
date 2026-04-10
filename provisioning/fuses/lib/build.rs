// Licensed under the Apache-2.0 license

use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(manifest_dir).join("../../..");

    let otp_mmap = project_root.join(caliptra_mcu_fusegen::OTP_CTRL_MMAP_DEFAULT_PATH);
    let otp_values = project_root.join(caliptra_mcu_fusegen::FUSE_VALUES_DEFAULT_PATH);

    let dest_path = project_root.join(caliptra_mcu_fusegen::FUSE_LIB_DEFAULT_PATH);

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    caliptra_mcu_fusegen::generate_fuse_values_file(&otp_mmap, &otp_values, &dest_path).unwrap();

    println!("cargo:rerun-if-changed={}", otp_mmap.display());
    println!("cargo:rerun-if-changed={}", otp_values.display());
}
