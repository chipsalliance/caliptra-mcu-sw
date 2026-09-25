// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_auth_man_types::OwnerAuthorizationManifest;
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, ImageCfg};
use clap::Subcommand;
use hex::ToHex;
use zerocopy::FromBytes;

#[derive(Subcommand)]
pub enum OwnerManifestCommands {
    /// Create an Owner Authorization Manifest
    Create {
        /// List of owner-only SoC images with format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<component_id>,<feature>[,<is_tcb>[,<is_ak_target>[,<network_filename>]]]
        #[arg(
            long = "owner_soc_image",
            value_name = "OWNER_SOC_IMAGE",
            num_args = 1..,
            required = true
        )]
        images: Vec<ImageCfg>,

        /// Output file path
        #[arg(long, value_name = "OUTPUT", required = true)]
        output: String,

        /// Owner Authorization Manifest SVN value
        #[arg(long = "svn", value_name = "SVN")]
        svn: Option<u32>,
    },
    /// Parse and display an Owner Authorization Manifest
    Parse {
        /// Path to the Owner Authorization Manifest file
        #[arg(value_name = "FILE")]
        file: String,
    },
}

pub fn create(owner_soc_images: &[ImageCfg], output: &str, svn: Option<u32>) -> Result<()> {
    let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
        owner_soc_images: Some(owner_soc_images.to_vec()),
        owner_manifest_svn: svn,
        ..Default::default()
    });

    let path = builder.get_owner_auth_manifest(Some(output))?;
    println!(
        "Owner Authorization Manifest created at: {}",
        path.display()
    );
    Ok(())
}

pub fn parse(file: &str) -> Result<()> {
    let data = std::fs::read(file)?;
    let manifest = OwnerAuthorizationManifest::read_from_bytes(&data).map_err(|error| {
        anyhow::anyhow!("Failed to parse Owner Authorization Manifest: {error:?}")
    })?;

    println!("=== Owner Authorization Manifest ===");
    println!();
    println!("Preamble:");
    println!("  Marker:  0x{:08X}", manifest.preamble.marker);
    println!("  Size:    {} bytes", manifest.preamble.size);
    println!("  Version: {}", manifest.preamble.version);
    println!("  SVN:     {}", manifest.preamble.svn);
    println!("  Flags:   0x{:08X}", manifest.preamble.flags);
    println!();

    let metadata_col = &manifest.image_metadata_col;
    let entry_count = metadata_col.entry_count as usize;
    println!("Image Metadata ({} entries):", entry_count);
    println!();

    for (index, metadata) in metadata_col
        .image_metadata_list
        .iter()
        .take(entry_count)
        .enumerate()
    {
        let load_addr =
            ((metadata.image_load_address.hi as u64) << 32) | metadata.image_load_address.lo as u64;
        let staging_addr = ((metadata.image_staging_address.hi as u64) << 32)
            | metadata.image_staging_address.lo as u64;
        let digest_hex: String = metadata.digest.encode_hex();

        println!("  [{}] FW ID: 0x{:08X}", index, metadata.fw_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_auth_man_types::OWNER_AUTH_MANIFEST_MARKER;
    use clap::Parser;
    use tempfile::tempdir;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: OwnerManifestCommands,
    }

    #[test]
    fn test_owner_manifest_create_cli_parse() {
        let cli = Cli::parse_from([
            "test",
            "create",
            "--owner_soc_image",
            "owner.bin,0x80000000,0x60000000,65536,2,65536,feature",
            "--output",
            "owner-manifest.bin",
            "--svn",
            "11",
        ]);

        match cli.command {
            OwnerManifestCommands::Create {
                images,
                output,
                svn,
            } => {
                assert_eq!(images.len(), 1);
                assert_eq!(images[0].image_id, 0x10000);
                assert_eq!(output, "owner-manifest.bin");
                assert_eq!(svn, Some(11));
            }
            _ => panic!("Expected OwnerManifestCommands::Create"),
        }
    }

    #[test]
    fn test_owner_manifest_create_and_parse() {
        let temp_dir = tempdir().unwrap();
        let image_path = temp_dir.path().join("owner.bin");
        let output_path = temp_dir.path().join("owner-manifest.bin");
        std::fs::write(&image_path, b"owner image").unwrap();

        create(
            &[ImageCfg {
                path: image_path,
                image_id: 0x10000,
                component_id: 0x10000,
                ..Default::default()
            }],
            output_path.to_str().unwrap(),
            Some(11),
        )
        .unwrap();

        let bytes = std::fs::read(&output_path).unwrap();
        let manifest = OwnerAuthorizationManifest::read_from_bytes(&bytes).unwrap();
        assert_eq!(manifest.preamble.marker, OWNER_AUTH_MANIFEST_MARKER);
        assert_eq!(manifest.preamble.svn, 11);
        assert_eq!(manifest.image_metadata_col.entry_count, 3);
        assert_eq!(
            manifest.image_metadata_col.image_metadata_list[0].fw_id,
            0x0000_0005
        );
        assert_eq!(
            manifest.image_metadata_col.image_metadata_list[1].fw_id,
            0x0000_0006
        );
        assert_eq!(
            manifest.image_metadata_col.image_metadata_list[2].fw_id,
            0x10000
        );
        parse(output_path.to_str().unwrap()).unwrap();
    }
}
