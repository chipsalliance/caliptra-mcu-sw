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

    let config =
        cbindgen::Config::from_file("cbindgen.toml").expect("Unable to find cbindgen.toml");

    let bindings =
        cbindgen::generate_with_config(&crate_dir, config).expect("Unable to generate bindings");

    // First write to a temporary location to get the content
    let temp_path = include_dir.join("temp_header.h");
    bindings.write_to_file(&temp_path);

    // Read the generated content
    let header_content =
        std::fs::read_to_string(&temp_path).expect("Unable to read generated header");

    // Prepend license header to the generated content
    let license_header = "// Licensed under the Apache-2.0 license\n\n/* Auto-generated from Rust caliptra-util-host library */\n\n";
    let final_content = format!("{}{}", license_header, header_content);

    println!("Adding license header to generated file");

    // Write the final content and clean up temp file
    std::fs::write(include_dir.join("caliptra_util_host.h"), final_content)
        .expect("Unable to write header file");
    std::fs::remove_file(&temp_path).ok(); // Ignore errors on cleanup

    println!("Generated caliptra_util_host.h - comprehensive C API from Rust");

    // Compile C test utilities that provide mock implementations
    cc::Build::new()
        .file("tests/caliptra_test_utils.c")
        .include("tests") // Include the tests directory for caliptra_test_utils.h
        .include("include") // Include the auto-generated header directory
        .compile("caliptra_test_utils");

    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=../caliptra-command-types/src/");
    println!("cargo:rerun-if-changed=tests/caliptra_test_utils.c");
    println!("cargo:rerun-if-changed=tests/caliptra_test_utils.h");
}
