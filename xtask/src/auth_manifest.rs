// Licensed under the Apache-2.0 license

use anyhow::Result;
use clap::Subcommand;
use mcu_builder::{CaliptraBuilder, ImageCfg};

#[derive(Subcommand)]
pub enum AuthManifestCommands {
    /// Create a Authentication Manifest
    Create {
        /// List of soc images with format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>
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
    );
    let path = builder.get_soc_manifest(None)?;
    std::fs::copy(&path, output)?;
    println!("Auth Manifest created at: {}", output);
    Ok(())
}
