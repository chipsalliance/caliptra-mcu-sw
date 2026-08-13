// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_auth_man_types::AuthorizationManifest;
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, ImageCfg};
use clap::{Args, Subcommand};
use hex::ToHex;
use std::path::{Path, PathBuf};
use zerocopy::FromBytes;

/// Paths to public key files used for authorization manifest creation and signing.
#[derive(Args, Clone, Debug, Default)]
pub struct AuthManifestKeyPaths {
    /// Path to Vendor FW Public Key PEM file
    #[arg(long = "vendor-fw-pub-key", value_name = "VENDOR_FW_PUB_KEY")]
    pub vendor_fw_pub_key: Option<String>,

    /// Path to Owner FW Public Key PEM file
    #[arg(long = "owner-fw-pub-key", value_name = "OWNER_FW_PUB_KEY")]
    pub owner_fw_pub_key: Option<String>,

    /// Path to Vendor Manifest Public Key PEM file
    #[arg(long = "vendor-man-pub-key", value_name = "VENDOR_MAN_PUB_KEY")]
    pub vendor_man_pub_key: Option<String>,

    /// Path to Owner Manifest Public Key PEM file
    #[arg(long = "owner-man-pub-key", value_name = "OWNER_MAN_PUB_KEY")]
    pub owner_man_pub_key: Option<String>,
}

/// Subcommands for creating and inspecting authorization manifests.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum AuthManifestCommands {
    /// Create an Authentication Manifest
    Create {
        /// List of soc images with format: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>,<component_id>,<feature>[,<is_tcb>[,<is_ak_target>[,<network_filename>]]]
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

        /// Path to export signing request JSON for offline signing
        #[arg(long = "signing-request", value_name = "SIGNING_REQUEST")]
        signing_request: Option<String>,

        #[command(flatten)]
        key_paths: AuthManifestKeyPaths,

        /// Auth Manifest SVN value
        #[arg(long = "svn", value_name = "SVN")]
        svn: Option<u32>,
    },
    /// Attach signatures to an unsigned auth manifest file and verify all signatures
    AttachSignatures {
        /// Path to the unsigned auth manifest binary
        #[arg(
            long = "unsigned-manifest",
            value_name = "UNSIGNED_MANIFEST",
            required = true
        )]
        unsigned_manifest: String,

        /// Path to the JSON file containing signatures
        #[arg(long = "signatures", value_name = "SIGNATURES", required = true)]
        signatures: String,

        /// Optional path to Vendor FW Public Key PEM file for signature verification
        #[arg(long = "vendor-fw-pub-key", value_name = "VENDOR_FW_PUB_KEY")]
        vendor_fw_pub_key: Option<String>,

        /// Optional path to Owner FW Public Key PEM file for signature verification
        #[arg(long = "owner-fw-pub-key", value_name = "OWNER_FW_PUB_KEY")]
        owner_fw_pub_key: Option<String>,

        /// Output file path for the signed manifest binary
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

/// Creates a signed or unsigned authorization manifest from SoC and MCU image configurations.
pub fn create(
    soc_images: &[ImageCfg],
    mcu_image: &ImageCfg,
    output: &str,
    signing_request_path: Option<&str>,
    key_paths: &AuthManifestKeyPaths,
    svn: Option<u32>,
) -> Result<()> {
    let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
        mcu_firmware: Some(mcu_image.clone().path),
        soc_images: Some(soc_images.to_vec()),
        mcu_image_cfg: Some(mcu_image.clone()),
        soc_manifest_svn: svn,
        ..Default::default()
    });

    if let Some(req_path) = signing_request_path {
        let vendor_fw_path = key_paths.vendor_fw_pub_key.as_ref().map(PathBuf::from);
        let owner_fw_path = key_paths.owner_fw_pub_key.as_ref().map(PathBuf::from);
        let vendor_man_path = key_paths.vendor_man_pub_key.as_ref().map(PathBuf::from);
        let owner_man_path = key_paths.owner_man_pub_key.as_ref().map(PathBuf::from);

        let builder_key_paths = caliptra_mcu_builder::AuthManifestPubKeysPaths {
            vendor_fw_ecc_pub_key: vendor_fw_path.as_deref(),
            owner_fw_ecc_pub_key: owner_fw_path.as_deref(),
            vendor_man_ecc_pub_key: vendor_man_path.as_deref(),
            owner_man_ecc_pub_key: owner_man_path.as_deref(),
            ..Default::default()
        };

        let (path, request) =
            builder.get_unsigned_auth_manifest(Some(output), Some(&builder_key_paths))?;

        let json_data = serde_json::to_string_pretty(&request)?;
        std::fs::write(req_path, json_data)?;
        println!("Unsigned Auth Manifest created at: {}", path.display());
        println!("Signing Request JSON exported to: {}", req_path);
    } else {
        let path = builder.get_soc_manifest(None)?;
        std::fs::copy(&path, output)?;
        println!("Auth Manifest created at: {}", output);
    }
    Ok(())
}

/// Attaches offline signatures to an unsigned authorization manifest binary and writes the signed binary.
pub fn attach_signatures(
    unsigned_manifest: &str,
    signatures: &str,
    vendor_fw_pub_key: Option<&str>,
    owner_fw_pub_key: Option<&str>,
    output: &str,
) -> Result<()> {
    let unsigned_path = Path::new(unsigned_manifest);
    let sigs_path = Path::new(signatures);
    let vendor_pub_path = vendor_fw_pub_key.map(Path::new);
    let owner_pub_path = owner_fw_pub_key.map(Path::new);
    let out_path = Path::new(output);

    caliptra_mcu_builder::attach_auth_manifest_signatures(
        unsigned_path,
        sigs_path,
        vendor_pub_path,
        owner_pub_path,
        out_path,
    )?;

    println!("Signed Auth Manifest written to: {}", output);
    Ok(())
}

/// Parses and prints the preamble and image metadata of an existing SoC manifest file.
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(clap::Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: AuthManifestCommands,
    }

    #[test]
    fn test_auth_manifest_create_cli_parse() {
        let args = vec![
            "test",
            "create",
            "--mcu_image",
            "runtime.bin,0xA8000000,0x60000000,1,2,0,feature",
            "--soc_image",
            "soc.bin,0x80000000,0x60000000,2,2,0,feature",
            "--output",
            "out.bin",
            "--signing-request",
            "req.json",
            "--vendor-man-pub-key",
            "vendor.pem",
            "--owner-man-pub-key",
            "owner.pem",
            "--svn",
            "5",
        ];

        let cli = Cli::parse_from(args);
        match cli.cmd {
            AuthManifestCommands::Create {
                output,
                signing_request,
                key_paths,
                svn,
                ..
            } => {
                assert_eq!(output, "out.bin");
                assert_eq!(signing_request, Some("req.json".to_string()));
                assert_eq!(key_paths.vendor_man_pub_key, Some("vendor.pem".to_string()));
                assert_eq!(key_paths.owner_man_pub_key, Some("owner.pem".to_string()));
                assert_eq!(svn, Some(5));
            }
            _ => panic!("Expected AuthManifestCommands::Create"),
        }
    }

    #[test]
    fn test_auth_manifest_attach_signatures_cli_parse() {
        let args = vec![
            "test",
            "attach-signatures",
            "--unsigned-manifest",
            "unsigned.bin",
            "--signatures",
            "sigs.json",
            "--vendor-fw-pub-key",
            "vendor_fw.pem",
            "--owner-fw-pub-key",
            "owner_fw.pem",
            "--output",
            "signed.bin",
        ];

        let cli = Cli::parse_from(args);
        match cli.cmd {
            AuthManifestCommands::AttachSignatures {
                unsigned_manifest,
                signatures,
                vendor_fw_pub_key,
                owner_fw_pub_key,
                output,
            } => {
                assert_eq!(unsigned_manifest, "unsigned.bin");
                assert_eq!(signatures, "sigs.json");
                assert_eq!(vendor_fw_pub_key, Some("vendor_fw.pem".to_string()));
                assert_eq!(owner_fw_pub_key, Some("owner_fw.pem".to_string()));
                assert_eq!(output, "signed.bin");
            }
            _ => panic!("Expected AuthManifestCommands::AttachSignatures"),
        }
    }
}
