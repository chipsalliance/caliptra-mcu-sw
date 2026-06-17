// Licensed under the Apache-2.0 license

//! # check_bundle example
//!
//! Demonstrates programmatic use of the `pk-hash-checker` internals by parsing
//! a firmware bundle supplied on the command line and printing both the vendor
//! and owner PK hashes.
//!
//! ## Running via WSL
//!
//! ```bash
//! # From the workspace root (WSL):
//! cargo run --example check_bundle -p caliptra-mcu-pk-hash-checker \
//!   -- /path/to/caliptra-fw-bundle.bin
//! ```
//!
//! ## Example output
//!
//! ```text
//! Bundle: /path/to/caliptra-fw-bundle.bin
//! Vendor PK hash : 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2900000000...
//! Owner  PK hash : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f...
//! ```

use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::{ImageManifest, IMAGE_MANIFEST_BYTE_SIZE};
use hex::ToHex;
use std::env;
use zerocopy::{transmute, IntoBytes};

fn main() {
    // -----------------------------------------------------------------------
    // Parse the single positional argument: path to the firmware bundle.
    // -----------------------------------------------------------------------
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: check_bundle <path-to-fw-bundle.bin>");
        eprintln!();
        eprintln!("Example (WSL):");
        eprintln!(
            "  cargo run --example check_bundle -p caliptra-mcu-pk-hash-checker \
             -- target/caliptra-fw-bundle.bin"
        );
        std::process::exit(2);
    }

    let bundle_path = &args[1];

    // -----------------------------------------------------------------------
    // Read the bundle from disk.
    // -----------------------------------------------------------------------
    let bundle_bytes = match std::fs::read(bundle_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: could not read `{bundle_path}`: {e}");
            std::process::exit(1);
        }
    };

    // -----------------------------------------------------------------------
    // Validate that the file is large enough to hold an ImageManifest.
    // -----------------------------------------------------------------------
    if bundle_bytes.len() < IMAGE_MANIFEST_BYTE_SIZE {
        eprintln!(
            "Error: file is too small ({} bytes); an ImageManifest requires {} bytes",
            bundle_bytes.len(),
            IMAGE_MANIFEST_BYTE_SIZE
        );
        std::process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Overlay the manifest bytes onto an ImageManifest.
    //
    // `transmute!` is a zerocopy macro that performs a compile-time size check
    // before reinterpreting the fixed-size byte array as the target type.
    // -----------------------------------------------------------------------
    let manifest_bytes: [u8; IMAGE_MANIFEST_BYTE_SIZE] = bundle_bytes[..IMAGE_MANIFEST_BYTE_SIZE]
        .try_into()
        .expect("slice length already validated above");
    let manifest: ImageManifest = transmute!(manifest_bytes);

    // -----------------------------------------------------------------------
    // Compute both PK hashes using the same method as the Caliptra builder:
    //   hash = from_hw_format(SHA384(raw_key_bytes))
    //
    // `from_hw_format` swaps the per-word byte order produced by the hardware
    // SHA engine back to the conventional big-endian representation used in
    // OTP fuses and displayed in the builder logs.
    // -----------------------------------------------------------------------
    let crypto = Crypto::default();

    let vendor_hw_hash = crypto
        .sha384_digest(manifest.preamble.vendor_pub_key_info.as_bytes())
        .expect("SHA-384 failed for vendor_pub_key_info");
    let vendor_hash: [u8; 48] = from_hw_format(&vendor_hw_hash);

    let owner_hw_hash = crypto
        .sha384_digest(manifest.preamble.owner_pub_keys.as_bytes())
        .expect("SHA-384 failed for owner_pub_keys");
    let owner_hash: [u8; 48] = from_hw_format(&owner_hw_hash);

    // -----------------------------------------------------------------------
    // Display results.
    // -----------------------------------------------------------------------
    println!("Bundle: {bundle_path}");
    println!("Vendor PK hash : {}", vendor_hash.encode_hex::<String>());
    println!("Owner  PK hash : {}", owner_hash.encode_hex::<String>());

    // -----------------------------------------------------------------------
    // Demonstrate comparison against a hard-coded reference value.
    //
    // In a real production script you would read this expected hash from a
    // separate trusted manifest or provision database.
    // -----------------------------------------------------------------------
    println!();
    println!("--- Comparison demo (against all-zero reference) ---");
    let reference_hash = [0u8; 48];
    let vendor_match = vendor_hash == reference_hash;
    let owner_match = owner_hash == reference_hash;
    println!(
        "Vendor hash {} all-zero reference",
        if vendor_match { "MATCHES" } else { "does NOT match" }
    );
    println!(
        "Owner  hash {} all-zero reference",
        if owner_match { "MATCHES" } else { "does NOT match" }
    );
}
