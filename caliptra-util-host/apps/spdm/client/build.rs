// Licensed under the Apache-2.0 license

//! Build script for caliptra-spdm-validator binary.
//!
//! Links the libspdm C libraries required by SPDM-Utils.
//! Set LIBSPDM_LIB_DIR to point to a directory containing the pre-built
//! libspdm static libraries (*.a files).

use std::env;
use std::path::PathBuf;

fn main() {
    let lib_dir = env::var("LIBSPDM_LIB_DIR").unwrap_or_else(|_| {
        // Default: look relative to the caliptra-util-host workspace target directory
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("../../../target/libspdm-lib")
            .to_string_lossy()
            .to_string()
    });

    let lib_dir = PathBuf::from(&lib_dir);
    if lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }

    println!("cargo:rustc-link-arg=-Wl,--start-group");
    println!("cargo:rustc-link-arg=-lspdm_common_lib");
    println!("cargo:rustc-link-arg=-lspdm_requester_lib");
    println!("cargo:rustc-link-arg=-lspdm_responder_lib");
    println!("cargo:rustc-link-arg=-lspdm_secured_message_lib");
    println!("cargo:rustc-link-arg=-lspdm_crypt_lib");
    println!("cargo:rustc-link-arg=-lspdm_crypt_ext_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_mctp_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_pcidoe_lib");
    println!("cargo:rustc-link-arg=-lmemlib");
    println!("cargo:rustc-link-arg=-lmalloclib");
    println!("cargo:rustc-link-arg=-ldebuglib");
    println!("cargo:rustc-link-arg=-lplatform_lib");
    println!("cargo:rustc-link-arg=-lrnglib");
    println!("cargo:rustc-link-arg=-lssl");
    println!("cargo:rustc-link-arg=-lcrypto");
    println!("cargo:rustc-link-arg=-lcryptlib_openssl");
    println!("cargo:rustc-link-arg=-Wl,--end-group");
}
