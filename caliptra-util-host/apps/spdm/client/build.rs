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
        println!("cargo:rustc-link-arg=-L{}", lib_dir.display());
    }

    // Link libspdm static archives by full path to avoid search-path issues
    let spdm_libs = [
        "libspdm_common_lib.a",
        "libspdm_requester_lib.a",
        "libspdm_responder_lib.a",
        "libspdm_secured_message_lib.a",
        "libspdm_crypt_lib.a",
        "libspdm_crypt_ext_lib.a",
        "libspdm_transport_mctp_lib.a",
        "libspdm_transport_pcidoe_lib.a",
        "libmemlib.a",
        "libmalloclib.a",
        "libdebuglib.a",
        "libplatform_lib.a",
        "librnglib.a",
        "libcryptlib_openssl.a",
    ];

    println!("cargo:rustc-link-arg=-Wl,--start-group");
    for lib_name in &spdm_libs {
        let lib_path = lib_dir.join(lib_name);
        if lib_path.exists() {
            println!("cargo:rustc-link-arg={}", lib_path.display());
        } else {
            // Fall back to -l flag
            let stem = lib_name
                .strip_prefix("lib")
                .unwrap()
                .strip_suffix(".a")
                .unwrap();
            println!("cargo:rustc-link-arg=-l{}", stem);
        }
    }
    println!("cargo:rustc-link-arg=-lssl");
    println!("cargo:rustc-link-arg=-lcrypto");
    println!("cargo:rustc-link-arg=-Wl,--end-group");
}
