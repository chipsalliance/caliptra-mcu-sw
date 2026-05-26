// Licensed under the Apache-2.0 license

//! Shared utility functions used across CLI subcommands.

use std::env;
use std::fs;
use std::path::PathBuf;

use ocptoken::cose_verify::DecodedCoseSign1;
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

/// COSE header label for x5chain (RFC 9360).
const COSE_HDR_PARAM_X5CHAIN: i64 = 33;

/// Extract the signing leaf certificate from a decoded COSE_Sign1.
///
/// Tries x5chain (label 33) in the unprotected header first. If not
/// present, falls back to the kid path: the leaf certificate is taken
/// from the provided external cert chain (root-first concatenated DER).
pub(crate) fn extract_signing_leaf(
    decoded: &DecodedCoseSign1,
    cert_chain_blob: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Try x5chain first
    if let Some(leaf) = try_extract_x5chain_leaf(decoded.unprotected_header()) {
        return Ok(leaf);
    }

    // Fall back to kid + external cert chain
    let has_kid = !decoded.unprotected_header().key_id.is_empty();
    if has_kid {
        let chain = cert_chain_blob.ok_or(
            "Token uses kid (no x5chain); --cert-chain is required",
        )?;
        if chain.is_empty() {
            return Err("Token uses kid but cert chain is empty".into());
        }
        return extract_leaf_from_chain(chain);
    }

    Err("No x5chain or kid found in unprotected header".into())
}

/// Extract the leaf (last) certificate from a root-first concatenated DER blob.
fn extract_leaf_from_chain(blob: &[u8]) -> Result<Vec<u8>, String> {
    let certs = split_der_certs(blob)?;
    certs
        .into_iter()
        .last()
        .ok_or_else(|| "Certificate chain is empty".into())
}

/// Try to extract the leaf certificate from x5chain (label 33).
/// Returns `None` if x5chain is not present.
fn try_extract_x5chain_leaf(header: &coset::Header) -> Option<Vec<u8>> {
    use coset::cbor::value::Value;
    use coset::Label;

    let value = header
        .rest
        .iter()
        .find_map(|(l, v)| {
            if *l == Label::Int(COSE_HDR_PARAM_X5CHAIN) {
                Some(v)
            } else {
                None
            }
        })?;

    match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        Value::Array(arr) => arr
            .first()
            .and_then(|v| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            }),
        _ => None,
    }
}

/// Split a concatenated DER blob into individual certificates.
fn split_der_certs(blob: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < blob.len() {
        if blob[offset] != 0x30 {
            return Err(format!(
                "Expected SEQUENCE tag (0x30) at offset {}, found 0x{:02x}",
                offset, blob[offset]
            ));
        }
        let (content_len, header_len) = parse_der_length(&blob[offset + 1..])?;
        let total_len = 1 + header_len + content_len;
        if offset + total_len > blob.len() {
            return Err(format!(
                "DER certificate at offset {} extends beyond input",
                offset
            ));
        }
        certs.push(blob[offset..offset + total_len].to_vec());
        offset += total_len;
    }

    Ok(certs)
}

/// Parse a DER length field. Returns (content_length, header_bytes_consumed).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("Truncated DER length".into());
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
        return Err("Invalid DER length encoding".into());
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | (data[1 + i] as usize);
    }
    Ok((len, 1 + num_bytes))
}
