// Licensed under the Apache-2.0 license

//! Shared utility functions used across CLI subcommands.

use std::env;
use std::fs;
use std::path::PathBuf;

use ocptoken::ta_store::{FsTrustAnchorStore, TrustAnchorStore};

/// Environment variable for the trust anchor store path.
const TA_STORE_PATH_ENV: &str = "TA_STORE_PATH";

/// Environment variable for the signed reference-value CoRIM directory path.
pub(crate) const SIGNED_REFVAL_CORIM_PATH: &str = "SIGNED_REFVAL_CORIM_PATH";

/// Load the Trust Anchor Store from a local directory specified by
/// the TA_STORE_PATH environment variable.  Exits the process on failure.
pub(crate) fn load_fs_ta_store() -> Box<dyn TrustAnchorStore> {
    let ta_store_path = match env::var(TA_STORE_PATH_ENV) {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!(
                "Environment variable {} is not set. \
                 Set it to the path of the trust anchor store directory \
                 (containing roots/ and optionally endorsement-certs/).",
                TA_STORE_PATH_ENV
            );
            std::process::exit(1);
        }
    };

    match FsTrustAnchorStore::load(&ta_store_path) {
        Ok(s) => {
            println!(
                "Loaded trust anchor store from '{}'",
                ta_store_path.display()
            );
            Box::new(s)
        }
        Err(e) => {
            eprintln!(
                "Failed to load trust anchor store '{}': {}",
                ta_store_path.display(),
                e
            );
            std::process::exit(1);
        }
    }
}

/// Load a binary evidence file from disk, printing its name and size.
/// Exits the process on failure.
pub(crate) fn load_evidence(path: &PathBuf) -> Vec<u8> {
    match fs::read(path) {
        Ok(b) => {
            println!(
                "Loaded evidence file '{}' ({} bytes)",
                path.display(),
                b.len()
            );
            b
        }
        Err(e) => {
            eprintln!("Failed to read evidence file '{}': {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

/// Extract the leaf (first) certificate from x5chain (label 33) in
/// a COSE unprotected header.
pub(crate) fn extract_x5chain_leaf(header: &coset::Header) -> Result<Vec<u8>, &'static str> {
    use coset::cbor::value::Value;
    use coset::Label;

    /// COSE header label for x5chain (RFC 9360).
    const COSE_HDR_PARAM_X5CHAIN: i64 = 33;

    let value = header
        .rest
        .iter()
        .find_map(|(l, v)| {
            if *l == Label::Int(COSE_HDR_PARAM_X5CHAIN) {
                Some(v)
            } else {
                None
            }
        })
        .ok_or("Missing x5chain (label 33) in unprotected header")?;

    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        Value::Array(arr) => arr
            .first()
            .and_then(|v| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or("x5chain array contains no valid certificate"),
        _ => Err("x5chain (label 33) has unexpected CBOR type"),
    }
}
