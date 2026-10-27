// Licensed under the Apache-2.0 license

use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(manifest_dir).join("../../..");

    let revision = caliptra_mcu_hw_revision::HardwareRevision::from_env()
        .unwrap_or_else(|error| panic!("{error}"));
    revision.emit_build_configuration();
    let otp_mmap = revision.otp_mmap(&project_root);
    let otp_values = project_root.join(caliptra_mcu_fusegen::FUSE_VALUES_DEFAULT_PATH);

    let dest_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("test.rs");

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    if let Err(e) =
        caliptra_mcu_fusegen::generate_fuse_values_file(&otp_mmap, &otp_values, &dest_path)
    {
        panic!("failed to generate fuse values: {:?}", e);
    }

    println!("cargo:rerun-if-changed={}", otp_mmap.display());
    println!("cargo:rerun-if-changed={}", otp_values.display());
}
