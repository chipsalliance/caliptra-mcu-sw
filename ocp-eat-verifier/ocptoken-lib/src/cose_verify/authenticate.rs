// Licensed under the Apache-2.0 license

//! Signer identification and authentication for COSE_Sign1 messages.
//!
//! In COSE (RFC 9052 §4.2), COSE_Sign1 carries a single signer whose
//! key is identified via header parameters — typically `x5chain`
//! (RFC 9360, label 33) or `kid` (label 4).
//!
//! This module extracts the signer's certificate from the COSE headers
//! and authenticates it against a [`TrustAnchorStore`].

use coset::{cbor::value::Value, Header, Label};

use crate::cose_verify::decode::DecodedCoseSign1;
use crate::cose_verify::{CoseSign1Error, CoseSign1Result};
use crate::ta_store::TrustAnchorStore;

/// COSE header label for x5chain (RFC 9360).
const COSE_HDR_PARAM_X5CHAIN: i64 = 33;

/// Which COSE headers to search for signer identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSelection {
    /// Search the protected header only.
    Protected,
    /// Search the unprotected header only.
    Unprotected,
    /// Search the protected header first, then the unprotected header (default).
    Both,
}

/// Which identification method to use for locating the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerIdMethod {
    /// Look for x5chain (label 33) only.
    X5chain,
    /// Look for kid (label 4) only.
    Kid,
    /// Try x5chain first, then fall back to kid (default).
    Both,
}

/// Options controlling how the signer is identified and authenticated.
///
/// The default searches both protected and unprotected headers, trying
/// x5chain first then kid — suitable when no profile constrains the
/// header layout.
#[derive(Debug, Clone)]
pub struct AuthenticateOptions {
    pub header: HeaderSelection,
    pub method: SignerIdMethod,
}

impl Default for AuthenticateOptions {
    fn default() -> Self {
        Self {
            header: HeaderSelection::Both,
            method: SignerIdMethod::Both,
        }
    }
}

/// Identify and authenticate the signer of a COSE_Sign1 message.
///
/// The `options` parameter controls which headers and identification
/// methods are tried.  With [`AuthenticateOptions::default()`] the
/// search order is (first match wins):
///
/// 1. x5chain (label 33) in the **protected** header
/// 2. x5chain (label 33) in the **unprotected** header
/// 3. kid (label 4) in the **protected** header
/// 4. kid (label 4) in the **unprotected** header
///
/// When `external_chain` is non-empty it is treated as a concatenated
/// DER certificate blob from the device (root-first order, e.g. from
/// SPDM GET_CERTIFICATE).  The device leaf (last cert in the blob) is
/// dropped and the remaining certs are appended (leaf-first) after the
/// x5chain certificates before authentication.
///
/// Pass an empty slice when no external chain is available.
pub fn authenticate_signer(
    decoded: &DecodedCoseSign1,
    ta_store: &dyn TrustAnchorStore,
    external_chain: &[u8],
    options: &AuthenticateOptions,
) -> CoseSign1Result<Vec<u8>> {
    let headers = select_headers(decoded, options.header);

    // Try x5chain
    if matches!(
        options.method,
        SignerIdMethod::X5chain | SignerIdMethod::Both
    ) {
        for header in &headers {
            if let Some(x5chain) = try_extract_x5chain(header) {
                let full_chain = build_chain(x5chain, external_chain)?;
                return Ok(ta_store.authenticate_chain(&full_chain)?);
            }
        }
    }

    // Try kid
    if matches!(options.method, SignerIdMethod::Kid | SignerIdMethod::Both) {
        for header in &headers {
            if !header.key_id.is_empty() {
                return Ok(ta_store.authenticate_by_kid(&header.key_id)?);
            }
        }
    }

    Err(CoseSign1Error::SignerNotFound)
}

/// Select headers to search based on [`HeaderSelection`].
fn select_headers<'a>(
    decoded: &'a DecodedCoseSign1,
    selection: HeaderSelection,
) -> Vec<&'a Header> {
    match selection {
        HeaderSelection::Protected => vec![decoded.protected_header()],
        HeaderSelection::Unprotected => vec![decoded.unprotected_header()],
        HeaderSelection::Both => {
            vec![decoded.protected_header(), decoded.unprotected_header()]
        }
    }
}

/// Extract the signer's leaf certificate from x5chain without authentication.
///
/// Checks the protected header first, then the unprotected header.
/// Returns `None` if x5chain is not present in either header.
pub fn extract_signer_key_cert(decoded: &DecodedCoseSign1) -> Option<Vec<u8>> {
    [decoded.protected_header(), decoded.unprotected_header()]
        .iter()
        .find_map(|h| try_extract_x5chain(h))
        .and_then(|certs| certs.into_iter().next())
}

/// Build the full authentication chain from x5chain certs and an
/// optional external DER blob.
fn build_chain(x5chain: Vec<Vec<u8>>, external_chain: &[u8]) -> CoseSign1Result<Vec<Vec<u8>>> {
    if external_chain.is_empty() {
        return Ok(x5chain);
    }

    let mut chain_certs =
        split_der_certs(external_chain).map_err(CoseSign1Error::CertificateError)?;
    // Drop the device leaf (last cert in root-first blob)
    if !chain_certs.is_empty() {
        chain_certs.pop();
    }
    // Reverse to leaf-first order, then prepend x5chain
    chain_certs.reverse();
    let mut full = x5chain;
    full.extend(chain_certs);
    Ok(full)
}

/// Try to extract the full x5chain certificate list from a single header.
/// Returns `None` if x5chain (label 33) is not present.
fn try_extract_x5chain(header: &Header) -> Option<Vec<Vec<u8>>> {
    let value = header.rest.iter().find_map(|(l, v)| {
        if *l == Label::Int(COSE_HDR_PARAM_X5CHAIN) {
            Some(v)
        } else {
            None
        }
    })?;

    match value {
        Value::Bytes(bytes) => Some(vec![bytes.clone()]),
        Value::Array(arr) => {
            let certs: Vec<Vec<u8>> = arr
                .iter()
                .filter_map(|v| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                None
            } else {
                Some(certs)
            }
        }
        _ => None,
    }
}

/// Split a concatenated DER blob into individual DER-encoded certificates.
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
