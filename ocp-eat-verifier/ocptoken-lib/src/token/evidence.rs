// Licensed under the Apache-2.0 license

use crate::cose_verify::{CoseSign1Verifier, CryptoBackend, DecodedCoseSign1};
use crate::error::{OcpEatError, OcpEatResult};
use crate::ta_store::TrustAnchorStore;
use coset::cbor::value::Value;
use coset::iana::Algorithm;
use coset::{Header, Label};

pub const OCP_EAT_CLAIMS_KEY_ID: &str = "";
pub const CBOR_TAG_CBOR: u64 = 55799;
pub const CBOR_TAG_CWT: u64 = 61;
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;

/// OCP EAT profile: CBOR self-describe (55799) -> CWT (61) -> COSE_Sign1 (18)
pub const OCP_EAT_TAGS: &[u64] = &[CBOR_TAG_CBOR, CBOR_TAG_CWT, CBOR_TAG_COSE_SIGN1];

/// Parsed and verified EAT evidence.
///
/// Wraps a `DecodedCoseSign1` from the common verification module,
/// adding OCP EAT-specific header validation and certificate chain
/// authentication via a [`TrustAnchorStore`].
pub struct Evidence<'a> {
    decoded: DecodedCoseSign1,
    ta_store: &'a dyn TrustAnchorStore,
}

impl<'a> Evidence<'a> {
    /// Decode and structurally validate a COSE_Sign1 with OCP EAT
    /// tag wrapping (55799 -> 61 -> 18).
    pub fn decode(slice: &[u8], ta_store: &'a dyn TrustAnchorStore) -> OcpEatResult<Self> {
        let decoded = DecodedCoseSign1::decode(slice, OCP_EAT_TAGS)?;

        verify_eat_protected_header(decoded.protected_header())?;

        Ok(Evidence { decoded, ta_store })
    }

    /// Authenticate the signing key against the Trust Anchor Store.
    ///
    /// `cert_chain_blob` is a concatenated DER certificate chain from
    /// the device (e.g. from SPDM GET_CERTIFICATE), ordered root-first:
    /// `[root | intermediate(s) | device_leaf]`.
    ///
    /// The device leaf (last cert in the blob) is dropped and replaced
    /// with the leaf certificate(s) from the x5chain in the evidence
    /// unprotected header. The resulting chain is passed to the Trust
    /// Anchor Store in leaf-first order for validation.
    ///
    /// Pass an empty slice if the x5chain already contains the full chain.
    ///
    /// Returns the DER-encoded authenticated leaf certificate on success.
    pub fn authenticate(&self, cert_chain_blob: &[u8]) -> OcpEatResult<Vec<u8>> {
        let x5chain = extract_x5chain(self.decoded.unprotected_header())?;

        let full_chain = if cert_chain_blob.is_empty() {
            // No external chain — use x5chain as the full chain
            x5chain
        } else {
            // Split the blob into individual certs (root-to-leaf order)
            let mut chain_certs = split_der_certs(cert_chain_blob)?;
            // Drop the device leaf (last cert)
            if !chain_certs.is_empty() {
                chain_certs.pop();
            }
            // Reverse to leaf-to-root order, then prepend x5chain
            chain_certs.reverse();
            let mut full = x5chain;
            full.extend(chain_certs);
            full
        };

        let authenticated_leaf = self.ta_store.authenticate_chain(&full_chain)?;
        Ok(authenticated_leaf)
    }

    /// Authenticate the signing key and cryptographically verify
    /// the COSE_Sign1 signature.
    ///
    /// Equivalent to calling [`authenticate`](Self::authenticate)
    /// followed by signature verification with the returned leaf cert.
    pub fn verify(
        &self,
        cert_chain_blob: &[u8],
        verifier: &CoseSign1Verifier<impl CryptoBackend>,
    ) -> OcpEatResult<()> {
        let authenticated_leaf = self.authenticate(cert_chain_blob)?;
        verifier.verify_ref(&self.decoded, &authenticated_leaf)?;
        Ok(())
    }
}

/// COSE header parameter label for x5chain (RFC 9360, label 33).
const COSE_HDR_PARAM_X5CHAIN: i64 = 33;

/// Extract x5chain certificate chain from a COSE header (label 33).
/// Returns DER-encoded certificates ordered leaf-first.
fn extract_x5chain(header: &Header) -> OcpEatResult<Vec<Vec<u8>>> {
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
        .ok_or(OcpEatError::InvalidToken(
            "Missing x5chain (label 33) in unprotected header",
        ))?;

    match value {
        // x5chain can be a single bstr (one cert) or an array of bstr
        Value::Bytes(bytes) => Ok(vec![bytes.clone()]),
        Value::Array(arr) => {
            let certs: Vec<Vec<u8>> = arr
                .iter()
                .filter_map(|v| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                Err(OcpEatError::InvalidToken("x5chain array contains no certificates"))
            } else {
                Ok(certs)
            }
        }
        _ => Err(OcpEatError::InvalidToken(
            "x5chain (label 33) has unexpected CBOR type",
        )),
    }
}

/// Split a concatenated DER blob into individual DER-encoded certificates.
fn split_der_certs(blob: &[u8]) -> OcpEatResult<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < blob.len() {
        if blob[offset] != 0x30 {
            return Err(OcpEatError::Certificate(format!(
                "Expected SEQUENCE tag (0x30) at offset {}, found 0x{:02x}",
                offset, blob[offset]
            )));
        }
        let (content_len, header_len) = parse_der_length(&blob[offset + 1..])?;
        let total_len = 1 + header_len + content_len;
        if offset + total_len > blob.len() {
            return Err(OcpEatError::Certificate(format!(
                "DER certificate at offset {} extends beyond input",
                offset
            )));
        }
        certs.push(blob[offset..offset + total_len].to_vec());
        offset += total_len;
    }

    Ok(certs)
}

/// Parse a DER length field. Returns (content_length, header_bytes_consumed).
fn parse_der_length(data: &[u8]) -> OcpEatResult<(usize, usize)> {
    if data.is_empty() {
        return Err(OcpEatError::Certificate(
            "Truncated DER length".into(),
        ));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
        return Err(OcpEatError::Certificate(
            "Invalid DER length encoding".into(),
        ));
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | (data[1 + i] as usize);
    }
    Ok((len, 1 + num_bytes))
}

/// EAT-specific protected header checks (algorithm + content-type).
fn verify_eat_protected_header(protected: &coset::Header) -> OcpEatResult<()> {
    let alg_ok = matches!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            Algorithm::ES384
        )) | Some(coset::RegisteredLabelWithPrivate::Assigned(
            Algorithm::ESP384
        ))
    );
    if !alg_ok {
        return Err(OcpEatError::InvalidToken(
            "Unexpected algorithm in protected header",
        ));
    }

    match &protected.content_type {
        Some(coset::RegisteredLabel::Assigned(coset::iana::CoapContentFormat::EatCwt)) => {}
        None => {}
        _other => {
            return Err(OcpEatError::InvalidToken(
                "Content format mismatch in protected header",
            ));
        }
    }

    Ok(())
}
