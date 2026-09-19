// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use caliptra_auth_man_types::AuthorizationManifest;
use caliptra_mcu_builder::{CaliptraBuilder, ComponentConfig, ImageCfg};
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
        #[arg(long = "soc_image", value_name = "SOC_IMAGE", num_args = 1..)]
        images: Vec<ImageCfg>,

        /// MCU Image metadata: <path>,<load_addr>,<staging_addr>,<image_id>,<exec_bit>
        /// Example: --mcu_image mcu-runtime.bin,0xA8000000,0x60000000,2,2
        #[arg(long = "mcu_image", value_name = "MCU_IMAGE", num_args = 1)]
        mcu_image: Option<ImageCfg>,

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

        /// TOML source of truth for component metadata
        #[arg(
            long = "component-config",
            visible_alias = "component_config",
            value_name = "COMPONENT_CONFIG",
            conflicts_with_all = ["images", "mcu_image", "svn"]
        )]
        component_config: Option<String>,

        /// Feature-specific component config override to apply
        #[arg(long, value_name = "FEATURE")]
        feature: Option<String>,

        /// Platform whose default component metadata should be used
        #[arg(long, default_value = "emulator", value_parser = ["emulator", "fpga"])]
        platform: String,
    },
    /// Verify an existing SoC authorization manifest against component metadata
    Verify {
        #[arg(long, value_name = "MANIFEST", required = true)]
        manifest: String,

        #[arg(
            long = "component-config",
            visible_alias = "component_config",
            value_name = "COMPONENT_CONFIG",
            required = true
        )]
        component_config: String,

        #[arg(long, value_name = "FEATURE")]
        feature: Option<String>,

        /// Platform whose default component metadata should be used
        #[arg(long, default_value = "emulator", value_parser = ["emulator", "fpga"])]
        platform: String,
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
pub struct CreateOptions<'a> {
    pub soc_images: &'a [ImageCfg],
    pub mcu_image: Option<&'a ImageCfg>,
    pub output: &'a str,
    pub signing_request_path: Option<&'a str>,
    pub key_paths: &'a AuthManifestKeyPaths,
    pub svn: Option<u32>,
    pub component_config_path: Option<&'a str>,
    pub feature: Option<&'a str>,
    pub platform: &'a str,
}

pub fn create(options: CreateOptions<'_>) -> Result<()> {
    let CreateOptions {
        soc_images,
        mcu_image,
        output,
        signing_request_path,
        key_paths,
        svn,
        component_config_path,
        feature,
        platform,
    } = options;
    if component_config_path.is_some() {
        let mut conflicts = Vec::new();
        if !soc_images.is_empty() {
            conflicts.push("soc_images");
        }
        if mcu_image.is_some() {
            conflicts.push("mcu_image");
        }
        if svn.is_some() {
            conflicts.push("svn");
        }
        if !conflicts.is_empty() {
            anyhow::bail!(
                "component_config conflicts with legacy metadata inputs: {}",
                conflicts.join(", ")
            );
        }
    }
    let resolved = component_config_path
        .map(ComponentConfig::from_file)
        .transpose()?
        .map(|config| config.resolve_for_platform(feature, platform == "fpga"))
        .transpose()?;
    if let Some(config) = &resolved {
        config.write_generated_configs(
            &caliptra_mcu_builder::target_dir(),
            "cargo xtask auth-manifest create --component-config",
        )?;
    }
    let resolved_mcu_image = resolved
        .as_ref()
        .and_then(|config| config.mcu_image.as_ref());
    let mcu_image = resolved_mcu_image.or(mcu_image).context(
        "MCU image metadata is required; pass --mcu-image or define mcu_image in --component-config",
    )?;
    let soc_images = resolved
        .as_ref()
        .map(|config| config.soc_images.as_slice())
        .unwrap_or(soc_images);
    let component_svn_validation = resolved
        .as_ref()
        .map(|config| config.component_svn_validation.clone());
    let soc_manifest_svn = resolved
        .as_ref()
        .map(|config| config.soc_manifest_svn)
        .or(svn);
    let mcu_firmware = if let Some(config) = &resolved {
        materialize_component_runtime(
            &mcu_image.path,
            &config.component_svn_manifest_bytes()?,
            &caliptra_mcu_builder::target_dir().join("generated"),
        )?
    } else {
        mcu_image.path.clone()
    };

    let mut builder = CaliptraBuilder::new(&caliptra_mcu_builder::CaliptraBuildArgs {
        mcu_firmware: Some(mcu_firmware),
        soc_images: Some(soc_images.to_vec()),
        mcu_image_cfg: Some(mcu_image.clone()),
        soc_manifest_svn,
        component_svn_validation,
        vendor: resolved.as_ref().map(|config| config.vendor.clone()),
        model: resolved.as_ref().map(|config| config.model.clone()),
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

fn materialize_component_runtime(
    runtime_path: &Path,
    component_manifest: &[u8],
    output_dir: &Path,
) -> Result<PathBuf> {
    let runtime = std::fs::read(runtime_path)
        .with_context(|| format!("failed to read MCU runtime {}", runtime_path.display()))?;
    let image_header_size = core::mem::size_of::<caliptra_mcu_image_header::McuImageHeader>();
    let already_prefixed = [0, image_header_size].into_iter().any(|offset| {
        runtime.get(offset..offset.saturating_add(component_manifest.len()))
            == Some(component_manifest)
    });
    if already_prefixed {
        return Ok(runtime_path.to_path_buf());
    }

    std::fs::create_dir_all(output_dir)?;
    let output = output_dir.join("mcu_runtime_with_component_svn.bin");
    let mut prefixed = Vec::with_capacity(component_manifest.len() + runtime.len());
    prefixed.extend_from_slice(component_manifest);
    prefixed.extend_from_slice(&runtime);
    std::fs::write(&output, prefixed)?;
    println!("Generated prefixed MCU runtime at: {}", output.display());
    Ok(output)
}

pub fn verify(
    manifest_path: &str,
    component_config_path: &str,
    feature: Option<&str>,
    platform: &str,
) -> Result<()> {
    let config = ComponentConfig::from_file(component_config_path)?
        .resolve_for_platform(feature, platform == "fpga")?;
    let data = std::fs::read(manifest_path)
        .with_context(|| format!("failed to read authorization manifest {manifest_path}"))?;
    let manifest = AuthorizationManifest::read_from_bytes(&data)
        .map_err(|error| anyhow::anyhow!("failed to parse authorization manifest: {error:?}"))?;

    if manifest.preamble.svn != config.soc_manifest_svn {
        anyhow::bail!(
            "invalid: manifest SVN {} does not match component config SVN {}",
            manifest.preamble.svn,
            config.soc_manifest_svn
        );
    }
    let expected = config
        .mcu_image
        .iter()
        .chain(config.soc_images.iter())
        .collect::<Vec<_>>();
    let actual_count = manifest.image_metadata_col.entry_count as usize;
    if actual_count != expected.len() {
        anyhow::bail!(
            "invalid: manifest has {actual_count} image entries, component config has {}",
            expected.len()
        );
    }
    if actual_count > manifest.image_metadata_col.image_metadata_list.len() {
        anyhow::bail!("invalid: manifest image entry count exceeds manifest capacity");
    }
    for (index, (actual, expected)) in manifest.image_metadata_col.image_metadata_list
        [..actual_count]
        .iter()
        .zip(expected)
        .enumerate()
    {
        let load_addr =
            ((actual.image_load_address.hi as u64) << 32) | actual.image_load_address.lo as u64;
        let staging_addr = ((actual.image_staging_address.hi as u64) << 32)
            | actual.image_staging_address.lo as u64;
        if actual.fw_id != expected.image_id
            || actual.component_id != expected.component_id
            || load_addr != expected.load_addr
            || staging_addr != expected.staging_addr
        {
            anyhow::bail!("invalid: manifest image entry {index} does not match component config");
        }
    }

    let mcu_image = config
        .mcu_image
        .as_ref()
        .context("component config does not define MCU image metadata")?;
    verify_component_svn_manifest(&mcu_image.path, &config.component_svn_manifest_bytes()?)?;

    println!("valid");
    Ok(())
}

fn verify_component_svn_manifest(runtime_path: &Path, expected: &[u8]) -> Result<()> {
    let runtime = std::fs::read(runtime_path)
        .with_context(|| format!("failed to read MCU runtime {}", runtime_path.display()))?;
    let image_header_size = core::mem::size_of::<caliptra_mcu_image_header::McuImageHeader>();
    let at_valid_offset = [0, image_header_size]
        .into_iter()
        .any(|offset| runtime.get(offset..offset.saturating_add(expected.len())) == Some(expected));
    if !at_valid_offset {
        anyhow::bail!(
            "invalid: MCU runtime {} does not contain the component SVN manifest at a valid header offset",
            runtime_path.display()
        );
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
    fn verifies_embedded_component_svn_manifest() {
        let runtime = tempfile::NamedTempFile::new().unwrap();
        let expected = [0x5a; 1024];
        let mut contents = vec![0; 8];
        contents.extend_from_slice(&expected);
        contents.extend_from_slice(&[0; 32]);
        std::fs::write(runtime.path(), contents).unwrap();

        verify_component_svn_manifest(runtime.path(), &expected).unwrap();
        assert!(verify_component_svn_manifest(runtime.path(), &[0xa5; 1024]).is_err());

        let misplaced = tempfile::NamedTempFile::new().unwrap();
        let mut contents = vec![0; 16];
        contents.extend_from_slice(&expected);
        std::fs::write(misplaced.path(), contents).unwrap();
        assert!(verify_component_svn_manifest(misplaced.path(), &expected).is_err());
    }

    #[test]
    fn materializes_component_runtime_without_double_prefixing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime = temp_dir.path().join("runtime.bin");
        let manifest = [0x5a; 1024];
        std::fs::write(&runtime, [0x13; 32]).unwrap();

        let prefixed = materialize_component_runtime(&runtime, &manifest, temp_dir.path()).unwrap();
        let bytes = std::fs::read(&prefixed).unwrap();
        assert_eq!(&bytes[..manifest.len()], &manifest);

        let unchanged =
            materialize_component_runtime(&prefixed, &manifest, temp_dir.path()).unwrap();
        assert_eq!(unchanged, prefixed);
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
                mcu_image,
                ..
            } => {
                assert_eq!(output, "out.bin");
                assert_eq!(signing_request, Some("req.json".to_string()));
                assert_eq!(key_paths.vendor_man_pub_key, Some("vendor.pem".to_string()));
                assert_eq!(key_paths.owner_man_pub_key, Some("owner.pem".to_string()));
                assert_eq!(svn, Some(5));
                assert!(mcu_image.is_some());
            }
            _ => panic!("Expected AuthManifestCommands::Create"),
        }
    }

    #[test]
    fn test_auth_manifest_verify_cli_parse() {
        let cli = Cli::parse_from([
            "test",
            "verify",
            "--manifest",
            "soc-manifest.bin",
            "--component-config",
            "components.toml",
            "--feature",
            "update",
        ]);
        match cli.cmd {
            AuthManifestCommands::Verify {
                manifest,
                component_config,
                feature,
                platform,
            } => {
                assert_eq!(manifest, "soc-manifest.bin");
                assert_eq!(component_config, "components.toml");
                assert_eq!(feature.as_deref(), Some("update"));
                assert_eq!(platform, "emulator");
            }
            _ => panic!("Expected AuthManifestCommands::Verify"),
        }
    }

    #[test]
    fn test_component_config_rejects_legacy_metadata() {
        let result = Cli::try_parse_from([
            "test",
            "create",
            "--component-config",
            "components.toml",
            "--soc_image",
            "soc.bin,0x80000000,0x60000000,2,2,0,feature",
            "--output",
            "out.bin",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn create_api_rejects_component_config_with_legacy_metadata() {
        let image = ImageCfg::default();
        let key_paths = AuthManifestKeyPaths::default();
        let error = create(CreateOptions {
            soc_images: &[image],
            mcu_image: None,
            output: "unused.bin",
            signing_request_path: None,
            key_paths: &key_paths,
            svn: None,
            component_config_path: Some("unused.toml"),
            feature: None,
            platform: "emulator",
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("component_config conflicts"));
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
