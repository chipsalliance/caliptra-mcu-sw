// Licensed under the Apache-2.0 license

//! Generate firmware registers using the new RDL-based generator.
//!
//! This generates registers similar to `registers.rs` but uses the new generator
//! and outputs to `registers/generated-firmware-new`.

use anyhow::{bail, Result};
use mcu_registers_generator_new::{generate_tock_registers_from_file_with_config, NameConfig};
use std::fs;
use std::path::Path;

use crate::registers::{HEADER_PREFIX, HEADER_SUFFIX};

/// Configuration for each register file to generate.
struct RegisterConfig {
    /// RDL file path (relative to project root)
    rdl_file: &'static str,
    /// Addrmap name in the RDL file
    addrmap: &'static str,
    /// Base address
    base_addr: usize,
    /// Output file name (without .rs extension)
    output_name: &'static str,
}

/// All register files to generate for firmware.
/// Based on the contents of registers/generated-firmware/src/
const REGISTER_CONFIGS: &[RegisterConfig] = &[
    // From soc_address_map.rdl
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/third_party/i3c-core/src/rdl/registers.rdl",
        addrmap: "I3CCSR",
        base_addr: 0x2000_4000,
        output_name: "i3c",
    },
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/src/mci/rtl/mci_top.rdl",
        addrmap: "mci_top",
        base_addr: 0x2100_0000,
        output_name: "mci",
    },
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/mbox_csr.rdl",
        addrmap: "mbox_csr",
        base_addr: 0xa002_0000,
        output_name: "mbox",
    },
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/sha512_acc_csr.rdl",
        addrmap: "sha512_acc_csr",
        base_addr: 0xa002_1000,
        output_name: "sha512_acc",
    },
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/soc_ifc_reg.rdl",
        addrmap: "soc_ifc_reg",
        base_addr: 0xa003_0000,
        output_name: "soc",
    },
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl.rdl",
        addrmap: "otp_ctrl",
        base_addr: 0x7000_0000,
        output_name: "otp_ctrl",
    },
    RegisterConfig {
        rdl_file: "hw/caliptra-ss/src/lc_ctrl/rtl/lc_ctrl.rdl",
        addrmap: "lc_ctrl",
        base_addr: 0x7000_0400,
        output_name: "lc_ctrl",
    },
    // From mcu.rdl
    RegisterConfig {
        rdl_file: "hw/el2_pic_ctrl.rdl",
        addrmap: "el2_pic_ctrl",
        base_addr: 0x6000_0000,
        output_name: "el2_pic_ctrl",
    },
    RegisterConfig {
        rdl_file: "hw/flash_ctrl.rdl",
        addrmap: "flash_ctrl",
        base_addr: 0x2000_8000,
        output_name: "primary_flash_ctrl",
    },
    RegisterConfig {
        rdl_file: "hw/flash_ctrl.rdl",
        addrmap: "flash_ctrl",
        base_addr: 0x2000_8800,
        output_name: "secondary_flash_ctrl",
    },
    RegisterConfig {
        rdl_file: "hw/axicdma.rdl",
        addrmap: "axicdma",
        base_addr: 0xa408_1000,
        output_name: "axicdma",
    },
    RegisterConfig {
        rdl_file: "hw/doe_mbox.rdl",
        addrmap: "doe_mbox",
        base_addr: 0x2F00_0000,
        output_name: "doe_mbox",
    },
];

/// Generate all firmware registers to the specified directory.
pub fn generate(project_root: &Path, check: bool) -> Result<()> {
    let dest_dir = project_root
        .join("registers")
        .join("generated-firmware-new")
        .join("src");
    let license_header = format!("{HEADER_PREFIX}{HEADER_SUFFIX}");

    // Create destination directory if it doesn't exist
    if !check {
        fs::create_dir_all(&dest_dir)?;
    }

    // Build name configuration with defaults
    let name_config = NameConfig::with_defaults();

    let mut generated_modules = Vec::new();
    let mut errors = Vec::new();

    for config in REGISTER_CONFIGS {
        let rdl_path = project_root.join(config.rdl_file);
        if !rdl_path.exists() {
            errors.push(format!(
                "RDL file not found: {} (skipping {})",
                config.rdl_file, config.output_name
            ));
            continue;
        }

        println!(
            "Generating {} from {} (addrmap: {}, base: 0x{:x})",
            config.output_name, config.rdl_file, config.addrmap, config.base_addr
        );

        match generate_tock_registers_from_file_with_config(
            &rdl_path,
            &[(config.addrmap, config.base_addr)],
            &name_config,
        ) {
            Ok(code) => {
                let output_path = dest_dir.join(format!("{}.rs", config.output_name));
                if check {
                    // In check mode, just verify we can generate
                    println!(
                        "  ✓ Would generate {} ({} bytes)",
                        config.output_name,
                        code.len()
                    );
                } else {
                    let content =
                        format!("{license_header}// Generated by xtask rdl-gen-firmware\n\n{code}");
                    fs::write(&output_path, &content)?;
                    println!(
                        "  ✓ Generated {} ({} bytes)",
                        config.output_name,
                        content.len()
                    );
                }
                generated_modules.push(config.output_name);
            }
            Err(e) => {
                errors.push(format!("Failed to generate {}: {}", config.output_name, e));
            }
        }
    }

    // Generate lib.rs
    if !check && !generated_modules.is_empty() {
        let lib_content = generate_lib_rs(&generated_modules);
        let lib_path = dest_dir.join("lib.rs");
        fs::write(&lib_path, &lib_content)?;
        println!("  ✓ Generated lib.rs");
    }

    // Report results
    println!("\n=== Generation Summary ===");
    println!("Generated: {} modules", generated_modules.len());
    if !errors.is_empty() {
        println!("\nErrors ({}):", errors.len());
        for error in &errors {
            println!("  ✗ {}", error);
        }
        if errors.len() > generated_modules.len() {
            bail!("Too many errors during generation");
        }
    }

    Ok(())
}

/// Generate lib.rs with module declarations
fn generate_lib_rs(modules: &[&str]) -> String {
    let mut content = String::new();
    content.push_str("// Licensed under the Apache-2.0 license\n");
    content.push_str("// Generated by xtask rdl-gen-firmware\n\n");
    content.push_str("#![no_std]\n\n");

    for module in modules {
        content.push_str(&format!("pub mod {};\n", module));
    }

    content
}
