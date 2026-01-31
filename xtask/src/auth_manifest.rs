// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_auth_man_types::AuthorizationManifest;
use clap::Subcommand;
use hex::ToHex;
use mcu_builder::{CaliptraBuilder, ImageCfg};
use zerocopy::FromBytes;

#[derive(Subcommand)]
pub enum AuthManifestCommands {
    /// Create a Authentication Manifest
    Create {
        /// List of soc images with format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<component_id>,<feature>
        /// Example: --soc_image image1.bin,0x80000000,0x60000000,2,2
        #[arg(long = "soc_image", value_name = "SOC_IMAGE", num_args = 1.., required = true)]
        images: Vec<ImageCfg>,

        /// MCU Image metadata: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>
        /// Example: --mcu_image mcu-runtime.bin,0xA8000000,0x60000000,2,2
        #[arg(
            long = "mcu_image",
            value_name = "MCU_IMAGE",
            num_args = 1,
            required = true
        )]
        mcu_image: ImageCfg,

        /// Output file path
        #[arg(long, value_name = "OUTPUT", required = true)]
        output: String,
    },
    /// Parse and display contents of an existing SoC manifest file
    Parse {
        /// Path to the SoC manifest file to parse
        #[arg(value_name = "FILE")]
        file: String,
    },
}

pub fn create(soc_images: &[ImageCfg], mcu_image: &ImageCfg, output: &str) -> Result<()> {
    let mut builder = CaliptraBuilder::new(
        false,
        None,
        None,
        None,
        None,
        Some(mcu_image.clone().path),
        Some(soc_images.to_vec()),
        Some(mcu_image.clone()),
        None,
        None,
        None,
    );
    let path = builder.get_soc_manifest(None)?;
    std::fs::copy(&path, output)?;
    println!("Auth Manifest created at: {}", output);
    Ok(())
}

pub fn parse(file: &str) -> Result<()> {
    let data = std::fs::read(file)?;

    let manifest = AuthorizationManifest::read_from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("Failed to parse SoC manifest: {:?}", e))?;

    println!("=== SoC Manifest ===");
    println!();

    // Preamble information
    let preamble = &manifest.preamble;
    println!("Preamble:");
    println!("  Marker:  0x{:08X}", preamble.marker);
    println!("  Size:    {} bytes", preamble.size);
    println!("  Version: {}", preamble.version);
    println!("  SVN:     {}", preamble.svn);
    println!("  Flags:   0x{:08X}", preamble.flags);
    println!();

    // Image metadata
    let metadata_col = &manifest.image_metadata_col;
    let entry_count = metadata_col.entry_count as usize;
    println!("Image Metadata ({} entries):", entry_count);
    println!();

    for i in 0..entry_count {
        if i >= metadata_col.image_metadata_list.len() {
            break;
        }
        let metadata = &metadata_col.image_metadata_list[i];
        let load_addr =
            ((metadata.image_load_address.hi as u64) << 32) | metadata.image_load_address.lo as u64;
        let staging_addr = ((metadata.image_staging_address.hi as u64) << 32)
            | metadata.image_staging_address.lo as u64;
        let digest_hex: String = metadata.digest.encode_hex();

        println!("  [{}] FW ID: 0x{:08X}", i, metadata.fw_id);
        println!("      Component ID:    0x{:08X}", metadata.component_id);
        println!("      Classification:  0x{:08X}", metadata.classification);
        println!("      Flags:           0x{:08X}", metadata.flags);
        println!("      Load Address:    0x{:016X}", load_addr);
        println!("      Staging Address: 0x{:016X}", staging_addr);
        println!("      Digest:          {}", digest_hex);
        println!();
    }

    Ok(())
}
