// Licensed under the Apache-2.0 license

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Create include directory if it doesn't exist
    let include_dir = PathBuf::from(&crate_dir).join("include");
    std::fs::create_dir_all(&include_dir).unwrap();

    // Auto-generate comprehensive C header from entire Rust caliptra-util-host library
    println!("Generating comprehensive C header from Rust library...");
    
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Unable to find cbindgen.toml");

    cbindgen::generate_with_config(&crate_dir, config)
        .expect("Unable to generate bindings")
        .write_to_file(include_dir.join("caliptra_util_host.h"));

    println!("Generated caliptra_util_host.h - comprehensive C API from Rust");

    // Compile C test utilities that provide mock implementations
    cc::Build::new()
        .file("tests/caliptra_test_utils.c")
        .include("tests")  // Include the tests directory for caliptra_test_utils.h
        .include("include") // Include the auto-generated header directory
        .compile("caliptra_test_utils");

    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=../caliptra-command-types/src/");
    println!("cargo:rerun-if-changed=tests/caliptra_test_utils.c");
    println!("cargo:rerun-if-changed=tests/caliptra_test_utils.h");
}