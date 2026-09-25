// Licensed under the Apache-2.0 license

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let config = cbindgen::Config {
        header: Some("// Licensed under the Apache-2.0 license".to_string()),
        language: cbindgen::Language::C,
        include_guard: Some("CALIPTRA_MCU_HW_MODEL_C_BINDING_CALIPTRA_MCU_MODEL_H".to_string()),
        cpp_compat: true,
        documentation: true,
        ..Default::default()
    };

    let out_dir = PathBuf::from(&crate_dir).join("out");
    std::fs::create_dir_all(&out_dir).expect("Unable to create cbindgen output directory");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_dir.join("caliptra_mcu_model.h"));
}
