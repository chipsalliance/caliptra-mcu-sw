// Licensed under the Apache-2.0 license

//! Temporary command to test the new RDL-based register generator.

use anyhow::Result;
use mcu_registers_generator_new::{generate_tock_registers_from_file_with_config, NameConfig};
use std::path::Path;

/// Generate registers from an RDL file using the new generator.
pub fn generate(
    rdl_file: &Path,
    addrmap: &str,
    base_addr: usize,
    output: Option<&Path>,
    strip_suffixes: &[String],
    strip_prefixes: &[String],
    no_default_strip: bool,
) -> Result<()> {
    println!("Generating registers from: {}", rdl_file.display());
    println!("Addrmap: {}, Base address: 0x{:x}", addrmap, base_addr);

    // Build name configuration
    let mut name_config = if no_default_strip {
        NameConfig::none()
    } else {
        NameConfig::with_defaults()
    };

    // Add custom suffixes
    for suffix in strip_suffixes {
        name_config = name_config.add_suffix(suffix);
    }

    // Add custom prefixes
    for prefix in strip_prefixes {
        name_config = name_config.add_prefix(prefix);
    }

    let code = generate_tock_registers_from_file_with_config(
        rdl_file,
        &[(addrmap, base_addr)],
        &name_config,
    )?;

    if let Some(output_path) = output {
        std::fs::write(output_path, &code)?;
        println!("Output written to: {}", output_path.display());
    } else {
        println!("\n--- Generated Code ---\n");
        println!("{}", code);
    }

    Ok(())
}
