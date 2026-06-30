// Licensed under the Apache-2.0 license

//! # pk-hash-checker
//!
//! A command-line tool that extracts the **vendor** or **owner** public-key hash
//! from a Caliptra firmware bundle (`.bin`) and optionally verifies it against a
//! user-supplied expected value.
//!
//! ## Background
//!
//! A Caliptra firmware bundle begins with an [`ImageManifest`] structure.  The
//! manifest preamble embeds two sets of public keys:
//!
//! - **Vendor keys** (`preamble.vendor_pub_key_info`) - keys controlled by the
//!   silicon vendor / firmware signer.
//! - **Owner keys** (`preamble.owner_pub_keys`) - keys injected by the platform
//!   owner at provisioning time.
//!
//! Caliptra's ROM authenticates firmware by comparing the SHA-384 hash of those
//! raw key bytes against a value burned into OTP fuses.  This tool lets you
//! inspect or validate those hashes without running the full hardware emulation
//! stack.
//!
//! ## Usage
//!
//! ```text
//! pk-hash-checker --bundle <PATH> --key-type <vendor|owner|both> [options]
//! ```
//!
//! ### Arguments
//!
//! | Flag               | Required | Description                                             |
//! |--------------------|----------|---------------------------------------------------------|
//! | `--bundle`         | Yes      | Path to the Caliptra firmware bundle binary file.       |
//! | `--key-type`       | Yes      | Which key set to check: `vendor`, `owner`, or `both`.   |
//! | `--expected-hash`  | No       | 96-character hex string to compare against.              |
//! | `--key-file`       | No       | Raw key-info blob. In `both` mode this is combined data. |
//! | `--reference-bundle`| No       | Compare against the same key-type hash in another bundle.|
//! | `--dump-key-info`   | No       | Save the key-info blob for later reuse.                  |
//!
//! ### Exit codes
//!
//! | Code | Meaning                                          |
//! |------|--------------------------------------------------|
//! | `0`  | Success (hash matches, or no expected hash given)|
//! | `1`  | Hash mismatch, parse failure, or I/O error.      |
//!
//! ## Comparison modes
//!
//! For `vendor` and `owner`, the tool computes one hash. For `both`, it computes
//! two hashes and can compare both against one combined key file.
//!
//! A **key-info blob** is the raw bytes of `ImageVendorPubKeyInfo` (vendor) or
//! `ImageOwnerPubKeys` (owner) as they appear at the start of a firmware bundle.
//! In `both` mode, the key file contains the vendor blob immediately followed by
//! the owner blob.
//!
//! ## Examples
//!
//! ```bash
//! # 1. Print the vendor public-key hash embedded in a bundle:
//! pk-hash-checker --bundle caliptra-fw-bundle.bin --key-type vendor
//!
//! # 2. Verify the owner PK hash against a known hex value:
//! pk-hash-checker \
//!   --bundle caliptra-fw-bundle.bin \
//!   --key-type owner \
//!   --expected-hash 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29...
//!
//! # 3. Save the vendor key-info blob from a trusted reference bundle:
//! pk-hash-checker \
//!   --bundle trusted-bundle.bin \
//!   --key-type vendor \
//!   --dump-key-info vendor-keys.bin
//!
//! # 4. Check a new bundle against the saved key-info blob:
//! pk-hash-checker \
//!   --bundle new-bundle.bin \
//!   --key-type vendor \
//!   --key-file vendor-keys.bin
//!
//! # 5. Compare two bundles directly (do they share the same owner keys?):
//! pk-hash-checker \
//!   --bundle bundle-a.bin \
//!   --key-type owner \
//!   --reference-bundle bundle-b.bin
//! ```

use anyhow::{bail, Context, Result};
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::{
    ImageManifest, ImageOwnerPubKeys, ImageVendorPubKeyInfo, IMAGE_MANIFEST_BYTE_SIZE,
    MANIFEST_MARKER,
};
use clap::{Parser, ValueEnum};
use hex::ToHex;
use std::path::{Path, PathBuf};
use zerocopy::{transmute, IntoBytes};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Verify vendor or owner public-key hashes in a Caliptra firmware bundle.
///
/// Reads the ImageManifest embedded at the start of the bundle, computes the
/// SHA-384 digest of the selected key-info bytes, and compares it to the
/// optional expected value.
#[derive(Debug, Parser)]
#[command(name = "pk-hash-checker", version, about)]
struct Cli {
    /// Path to the Caliptra firmware bundle binary (e.g. caliptra-fw-bundle.bin).
    ///
    /// The file must start with a valid `ImageManifest` structure.  Additional
    /// FMC / runtime payload bytes after the manifest are ignored.
    #[arg(long)]
    bundle: PathBuf,

    /// Which public-key set to hash: `vendor`, `owner`, or `both`.
    #[arg(long, value_enum)]
    key_type: KeyType,

    /// Expected SHA-384 hash expressed as a 96-character lowercase hex string.
    ///
    /// Mutually exclusive with `--key-file` and `--reference-bundle`.
    /// When supplied the tool exits with code 0 on match and 1 on mismatch.
    /// When omitted the tool prints the computed hash and exits with code 0.
    #[arg(long, conflicts_with_all = ["key_file", "reference_bundle"])]
    expected_hash: Option<String>,

    /// Path to a saved raw key-info binary blob to compare against.
    ///
    /// The file must contain the exact bytes of `ImageVendorPubKeyInfo` (for
    /// `--key-type vendor`) or `ImageOwnerPubKeys` (for `--key-type owner`). In
    /// `both` mode, the file must contain the vendor blob immediately followed
    /// by the owner blob.
    /// Create one from a trusted bundle with `--dump-key-info`.
    #[arg(long, conflicts_with_all = ["expected_hash", "reference_bundle"])]
    key_file: Option<PathBuf>,

    /// Path to a second firmware bundle to compare key info against.
    ///
    /// Extracts the same key type from the reference bundle, computes its hash,
    /// and compares it to the hash from `--bundle`.  Useful for checking whether
    /// two bundles share the same vendor or owner keys.
    #[arg(long, conflicts_with_all = ["expected_hash", "key_file"])]
    reference_bundle: Option<PathBuf>,

    /// Extract the raw key-info blob from `--bundle` and write it to this path.
    ///
    /// The saved file can later be passed to `--key-file` on other bundles.
    /// Can be combined with any comparison flag; the dump happens first.
    #[arg(long)]
    dump_key_info: Option<PathBuf>,

    /// Print additional detail about the manifest preamble (key counts, etc.).
    #[arg(long, short)]
    verbose: bool,
}

/// The public-key set to inspect inside the firmware bundle.
#[derive(Clone, Debug, ValueEnum)]
enum KeyType {
    /// Hash the vendor public-key info block.
    Vendor,
    /// Hash the owner public-key block.
    Owner,
    /// Both vendor and owner key types.
    Both,
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Parse the [`ImageManifest`] from the leading bytes of a firmware bundle.
///
/// # Errors
///
/// Returns an error if the file is too short to contain a full manifest or if
/// the byte slice cannot be interpreted as a valid manifest.
fn parse_manifest(bundle_bytes: &[u8]) -> Result<ImageManifest> {
    if bundle_bytes.len() < IMAGE_MANIFEST_BYTE_SIZE {
        bail!(
            "Bundle is {} bytes, but an ImageManifest requires at least {} bytes",
            bundle_bytes.len(),
            IMAGE_MANIFEST_BYTE_SIZE
        );
    }

    // Safety: IMAGE_MANIFEST_BYTE_SIZE == size_of::<ImageManifest>() by
    // definition; the `transmute!` macro performs a compile-time size check.
    let bytes: [u8; IMAGE_MANIFEST_BYTE_SIZE] = bundle_bytes[..IMAGE_MANIFEST_BYTE_SIZE]
        .try_into()
        .context("Failed to copy manifest bytes into fixed-size array")?;

    let manifest: ImageManifest = transmute!(bytes);

    if manifest.size != IMAGE_MANIFEST_BYTE_SIZE as u32 {
        bail!(
            "Invalid Manifest size: {}, expected {}",
            manifest.size,
            IMAGE_MANIFEST_BYTE_SIZE
        );
    }

    if manifest.marker != MANIFEST_MARKER {
        bail!(
            "Invalid Manifest marker: {:#010x}, expected {:#010x}",
            manifest.marker,
            MANIFEST_MARKER
        );
    }

    Ok(manifest)
}

/// Validate a user-supplied expected-hash string.
///
/// Accepts a 96-character lowercase or uppercase hex string (48 bytes).
///
/// # Errors
///
/// Returns an error if the string is not valid hex or not exactly 96 characters.
fn parse_expected_hash(hex_str: &str) -> Result<[u8; 48]> {
    let decoded = hex::decode(hex_str.trim())
        .with_context(|| format!("Expected hash is not valid hex: `{hex_str}`"))?;

    if decoded.len() != 48 {
        bail!(
            "Expected hash must be 48 bytes (96 hex chars), got {} bytes ({} hex chars)",
            decoded.len(),
            hex_str.trim().len()
        );
    }

    let mut out = [0u8; 48];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Extract the raw key-info bytes for the selected key type from a manifest.
///
/// - **vendor** -> bytes of `manifest.preamble.vendor_pub_key_info`
/// - **owner**  -> bytes of `manifest.preamble.owner_pub_keys`
///
/// These byte slices are what gets SHA-384 hashed to produce the PK hash that
/// Caliptra's ROM compares against OTP fuses.
fn key_info_bytes<'a>(manifest: &'a ImageManifest, key_type: &KeyType) -> &'a [u8] {
    match key_type {
        KeyType::Vendor => manifest.preamble.vendor_pub_key_info.as_bytes(),
        KeyType::Owner => manifest.preamble.owner_pub_keys.as_bytes(),
        KeyType::Both => unreachable!("combined mode uses combined_key_info_bytes"),
    }
}

/// Return the vendor bytes followed by the owner bytes for `--key-type both`.
fn combined_key_info_bytes(manifest: &ImageManifest) -> Vec<u8> {
    let vendor = manifest.preamble.vendor_pub_key_info.as_bytes();
    let owner = manifest.preamble.owner_pub_keys.as_bytes();
    let mut bytes = Vec::with_capacity(vendor.len() + owner.len());
    bytes.extend_from_slice(vendor);
    bytes.extend_from_slice(owner);
    bytes
}

/// Load and validate a raw key-info blob from a file.
///
/// Validates that the file is exactly the right size for the selected key type
/// (`ImageVendorPubKeyInfo` or `ImageOwnerPubKeys`) before returning its bytes.
///
/// # Errors
///
/// Returns an error if the file cannot be read or its size does not match the
/// expected struct size for `key_type`.
fn load_key_file(path: &Path, key_type: &KeyType) -> Result<Vec<u8>> {
    let (expected_size, type_name) = match key_type {
        KeyType::Vendor => (
            std::mem::size_of::<ImageVendorPubKeyInfo>(),
            "ImageVendorPubKeyInfo",
        ),
        KeyType::Owner => (
            std::mem::size_of::<ImageOwnerPubKeys>(),
            "ImageOwnerPubKeys",
        ),
        KeyType::Both => unreachable!("combined mode uses load_combined_key_file"),
    };

    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read key file `{}`", path.display()))?;

    if bytes.len() != expected_size {
        bail!(
            "Key file `{}` is {} bytes but `{}` requires exactly {} bytes.\n\
             Tip: generate a valid key file with:\n  \
             pk-hash-checker --bundle <BUNDLE> --key-type {} --dump-key-info <OUTPUT>",
            path.display(),
            bytes.len(),
            type_name,
            expected_size,
            match key_type {
                KeyType::Vendor => "vendor",
                KeyType::Owner => "owner",
                KeyType::Both => "both",
            }
        );
    }

    Ok(bytes)
}

/// Load a combined key file containing vendor bytes followed by owner bytes.
fn load_combined_key_file(path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let vendor_size = std::mem::size_of::<ImageVendorPubKeyInfo>();
    let owner_size = std::mem::size_of::<ImageOwnerPubKeys>();
    let expected_size = vendor_size + owner_size;

    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read key file `{}`", path.display()))?;

    if bytes.len() != expected_size {
        bail!(
            "Combined key file `{}` is {} bytes but requires exactly {} bytes (vendor {} + owner {}).",
            path.display(),
            bytes.len(),
            expected_size,
            vendor_size,
            owner_size
        );
    }

    Ok((bytes[..vendor_size].to_vec(), bytes[vendor_size..].to_vec()))
}

/// Compute the SHA-384 hash of an arbitrary byte slice.
///
/// Used to hash both in-bundle key info and external key files / reference
/// bundles so the same hash function is applied in every comparison path.
fn sha384_of(bytes: &[u8]) -> Result<[u8; 48]> {
    let crypto = Crypto::default();
    let hw_hash = crypto
        .sha384_digest(bytes)
        .context("SHA-384 digest failed")?;
    Ok(from_hw_format(&hw_hash))
}

/// Print verbose information about the manifest preamble.
fn print_verbose_info(manifest: &ImageManifest, key_type: &KeyType) {
    println!("  Manifest marker    : {:#010x}", manifest.marker);
    println!("  Manifest size      : {} bytes", manifest.size);
    println!(
        "  Vendor ECC key idx : {}",
        manifest.preamble.vendor_ecc_pub_key_idx
    );
    match key_type {
        KeyType::Vendor => println!(
            "  Key-info blob size : {} bytes (ImageVendorPubKeyInfo)",
            key_info_bytes(manifest, key_type).len()
        ),
        KeyType::Owner => println!(
            "  Key-info blob size : {} bytes (ImageOwnerPubKeys)",
            key_info_bytes(manifest, key_type).len()
        ),
        KeyType::Both => println!(
            "  Key-info blob size : {} bytes (combined vendor + owner)",
            combined_key_info_bytes(manifest).len()
        ),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    let comparison_modes = [
        cli.expected_hash.is_some(),
        cli.key_file.is_some(),
        cli.reference_bundle.is_some(),
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();

    if matches!(cli.key_type, KeyType::Both) {
        if cli.expected_hash.is_some() || cli.reference_bundle.is_some() {
            bail!("--key-type both only supports --key-file or --dump-key-info");
        }
        if comparison_modes > 1 {
            bail!("--key-type both accepts at most one comparison flag");
        }
    } else if comparison_modes > 1 {
        bail!("--expected-hash, --key-file, and --reference-bundle are mutually exclusive");
    }

    // ------------------------------------------------------------------
    // 1. Read and parse the primary firmware bundle.
    // ------------------------------------------------------------------
    let bundle_bytes = std::fs::read(&cli.bundle).with_context(|| {
        format!(
            "Failed to read firmware bundle from `{}`",
            cli.bundle.display()
        )
    })?;

    let manifest = parse_manifest(&bundle_bytes).with_context(|| {
        format!(
            "Failed to parse ImageManifest from `{}`",
            cli.bundle.display()
        )
    })?;

    if cli.verbose {
        println!("Bundle: {}", cli.bundle.display());
        print_verbose_info(&manifest, &cli.key_type);
    }

    // ------------------------------------------------------------------
    // 2. Optional: dump the raw key-info blob to a file.
    //
    // This can be done independently of any comparison.  The output file
    // is the exact bytes of `ImageVendorPubKeyInfo` or `ImageOwnerPubKeys`
    // and can be passed to `--key-file` in future invocations.
    // ------------------------------------------------------------------
    if let Some(ref dump_path) = cli.dump_key_info {
        let blob = match cli.key_type {
            KeyType::Vendor | KeyType::Owner => key_info_bytes(&manifest, &cli.key_type).to_vec(),
            KeyType::Both => combined_key_info_bytes(&manifest),
        };
        let blob_len = blob.len();
        std::fs::write(dump_path, blob).with_context(|| {
            format!("Failed to write key-info blob to `{}`", dump_path.display())
        })?;
        println!(
            "Key-info blob ({} bytes) written to `{}`.",
            blob_len,
            dump_path.display()
        );
    }

    // ------------------------------------------------------------------
    // 3. Compute the PK hash from the primary bundle.
    // ------------------------------------------------------------------
    let label = match cli.key_type {
        KeyType::Vendor => "vendor",
        KeyType::Owner => "owner",
        KeyType::Both => "both",
    };
    let vendor_hash = sha384_of(manifest.preamble.vendor_pub_key_info.as_bytes())?;
    let owner_hash = sha384_of(manifest.preamble.owner_pub_keys.as_bytes())?;
    match cli.key_type {
        KeyType::Vendor => {
            println!("vendor PK hash: {}", vendor_hash.encode_hex::<String>())
        }
        KeyType::Owner => {
            println!("owner PK hash: {}", owner_hash.encode_hex::<String>())
        }
        KeyType::Both => {
            println!("vendor PK hash: {}", vendor_hash.encode_hex::<String>());
            println!("owner PK hash: {}", owner_hash.encode_hex::<String>());
        }
    }

    // ------------------------------------------------------------------
    // 4. Comparison (exactly one of: --expected-hash / --key-file /
    //    --reference-bundle).  If none supplied, just print and exit.
    // ------------------------------------------------------------------
    if matches!(cli.key_type, KeyType::Both) {
        if cli.expected_hash.is_some() || cli.reference_bundle.is_some() {
            bail!("--key-type both does not support --expected-hash or --reference-bundle");
        }

        if let Some(ref key_file_path) = cli.key_file {
            let (vendor_file_bytes, owner_file_bytes) = load_combined_key_file(key_file_path)?;
            let vendor_file_hash = sha384_of(&vendor_file_bytes)?;
            let owner_file_hash = sha384_of(&owner_file_bytes)?;

            println!(
                "combined key file (`{}`) vendor hash: {}",
                key_file_path.display(),
                vendor_file_hash.encode_hex::<String>()
            );
            println!(
                "combined key file (`{}`) owner hash: {}",
                key_file_path.display(),
                owner_file_hash.encode_hex::<String>()
            );

            let passed_vendor = compare(
                "vendor",
                &vendor_hash,
                &vendor_hash.encode_hex::<String>(),
                &vendor_file_hash,
                &vendor_file_hash.encode_hex::<String>(),
            );

            let passed_owner = compare(
                "owner",
                &owner_hash,
                &owner_hash.encode_hex::<String>(),
                &owner_file_hash,
                &owner_file_hash.encode_hex::<String>(),
            );

            if !passed_owner || !passed_vendor {
                std::process::exit(1);
            }
        }

        return Ok(());
    }

    let computed_hash = match cli.key_type {
        KeyType::Vendor => vendor_hash,
        KeyType::Owner => owner_hash,
        KeyType::Both => [0u8; 48], // unreachable!("handled above")
    };
    let computed_hex: String = computed_hash.encode_hex();

    if let Some(ref expected_str) = cli.expected_hash {
        // -- 4a. Hex string comparison -----------------------------------
        let expected_bytes = parse_expected_hash(expected_str)?;
        compare_and_exit(
            label,
            &computed_hash,
            &computed_hex,
            &expected_bytes,
            expected_str.trim(),
        );
    } else if let Some(ref key_file_path) = cli.key_file {
        // -- 4b. Raw key-info blob comparison ----------------------------
        //
        // Hash the blob from the file the same way the bundle's key info is
        // hashed, then compare.  The file must be exactly
        // size_of::<ImageVendorPubKeyInfo>() or size_of::<ImageOwnerPubKeys>()
        // bytes depending on `--key-type`.
        let blob = load_key_file(key_file_path, &cli.key_type)?;
        let file_hash = sha384_of(&blob)?;
        let file_hex: String = file_hash.encode_hex();

        println!(
            "Key file PK hash (`{}`): {}",
            key_file_path.display(),
            file_hex
        );
        compare_and_exit(label, &computed_hash, &computed_hex, &file_hash, &file_hex);
    } else if let Some(ref ref_path) = cli.reference_bundle {
        // -- 4c. Reference bundle comparison -----------------------------
        //
        // Extract the same key-type info from the reference bundle, hash it,
        // and compare against the primary bundle's hash.
        let ref_bytes = std::fs::read(ref_path).with_context(|| {
            format!(
                "Failed to read reference bundle from `{}`",
                ref_path.display()
            )
        })?;
        let ref_manifest = parse_manifest(&ref_bytes).with_context(|| {
            format!(
                "Failed to parse ImageManifest from reference bundle `{}`",
                ref_path.display()
            )
        })?;

        let ref_key_bytes = key_info_bytes(&ref_manifest, &cli.key_type);
        let ref_hash = sha384_of(ref_key_bytes)?;
        let ref_hex: String = ref_hash.encode_hex();

        println!(
            "Reference bundle {label} PK hash (`{}`): {}",
            ref_path.display(),
            ref_hex
        );
        compare_and_exit(label, &computed_hash, &computed_hex, &ref_hash, &ref_hex);
    }

    Ok(())
}

/// Compare `computed` against `expected`, print PASS/FAIL
/// return true if they match, false if there is a mismatch.
fn compare(
    label: &str,
    computed: &[u8; 48],
    computed_hex: &str,
    expected: &[u8; 48],
    expected_display: &str,
) -> bool {
    if computed == expected {
        println!("PASS: {label} PK hash matches.");
        true
    } else {
        eprintln!(
            "FAIL: {label} PK hash mismatch.\n  computed : {computed_hex}\n  expected : {expected_display}"
        );
        false
    }
}

/// Compare `computed` against `expected`, print PASS/FAIL, and exit with code 1
/// on mismatch.
fn compare_and_exit(
    label: &str,
    computed: &[u8; 48],
    computed_hex: &str,
    expected: &[u8; 48],
    expected_display: &str,
) {
    if !compare(label, computed, computed_hex, expected, expected_display) {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse_expected_hash` should reject strings that are too short.
    #[test]
    fn test_parse_expected_hash_too_short() {
        let result = parse_expected_hash("deadbeef");
        assert!(result.is_err());
    }

    /// `parse_expected_hash` should reject non-hex characters.
    #[test]
    fn test_parse_expected_hash_invalid_hex() {
        let result = parse_expected_hash(&"zz".repeat(48));
        assert!(result.is_err());
    }

    /// `parse_expected_hash` should succeed for a valid 96-char hex string.
    #[test]
    fn test_parse_expected_hash_valid() {
        let valid = "ab".repeat(48); // 96 hex chars = 48 bytes
        let bytes = parse_expected_hash(&valid).unwrap();
        assert_eq!(bytes, [0xabu8; 48]);
    }

    /// `parse_manifest` should reject a bundle that is shorter than the manifest.
    #[test]
    fn test_parse_manifest_too_short() {
        let short_buf = vec![0u8; 10];
        let result = parse_manifest(&short_buf);
        assert!(result.is_err());
    }
}
