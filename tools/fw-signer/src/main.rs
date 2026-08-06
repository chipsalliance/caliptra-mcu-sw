// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use caliptra_mcu_fw_signer::{generate_offline_signatures, KeyManifest};
use clap::Parser;
use std::path::PathBuf;

/// Command line arguments for `fw-signer`.
#[derive(Parser, Debug)]
#[command(
    name = "fw-signer",
    about = "Generate signatures.json from signing_request.json using a key manifest for Caliptra auth manifests"
)]
pub struct Args {
    /// Path to input signing_request.json file.
    #[arg(short = 'r', long)]
    pub signing_request: PathBuf,

    /// Path to JSON key manifest file specifying key paths or OpenSSL provider key names.
    #[arg(short = 'k', long)]
    pub key_manifest: PathBuf,

    /// Optional OpenSSL 3 provider name to load for cryptographic signing (e.g., "pkcs11", "default", "fips").
    #[arg(long)]
    pub openssl_provider: Option<String>,

    /// Path to output signatures.json file.
    #[arg(short = 'o', long)]
    pub output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(provider_name) = &args.openssl_provider {
        openssl::provider::Provider::load(None, provider_name)
            .with_context(|| format!("Failed to load OpenSSL provider '{}'", provider_name))?;
    }

    let manifest_content = std::fs::read_to_string(&args.key_manifest).with_context(|| {
        format!(
            "Failed to read key manifest file {}",
            args.key_manifest.display()
        )
    })?;
    let key_manifest: KeyManifest = serde_json::from_str(&manifest_content).with_context(|| {
        format!(
            "Failed to parse JSON key manifest {}",
            args.key_manifest.display()
        )
    })?;

    let sigs = generate_offline_signatures(&args.signing_request, &key_manifest, &args.output)?;
    println!(
        "Successfully generated offline signatures at {}",
        args.output.display()
    );
    let _ = sigs;
    Ok(())
}
