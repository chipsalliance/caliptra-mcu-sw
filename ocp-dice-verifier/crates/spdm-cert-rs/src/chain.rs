// Licensed under the Apache-2.0 license

//! DMTF SPDM Certificate Chain decoder.
//!
//! Handles SPDM certificate chain unpacking, root hash verification,
//! and splitting concatenated ASN.1 DER certificates.

use crate::error::{Result, SpdmCertError};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Minimum SPDM cert chain header length:
/// 2 bytes `Length` + 2 bytes `Reserved` = 4 bytes.
pub const SPDM_CERT_CHAIN_HEADER_LEN: usize = 4;

/// Supported SPDM BaseHashAlgo digest sizes (SHA-384, SHA-256, SHA-512).
pub const SPDM_CANDIDATE_HASH_LENS: [usize; 3] = [48, 32, 64];

/// SPDM Certificate Chain structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmCertChain {
    /// Indicates whether the input had an SPDM 4-byte header.
    pub has_spdm_header: bool,

    /// Root certificate hash extracted from SPDM header (if present).
    pub root_hash: Option<Vec<u8>>,

    /// Individual ASN.1 DER-encoded certificates in issuance order (Root -> Leaf).
    pub certs: Vec<Vec<u8>>,
}

impl SpdmCertChain {
    /// Decodes an SPDM certificate chain blob when the negotiated SPDM `BaseHashAlgo`
    /// digest size (`hash_len`: 32, 48, or 64 bytes) is known.
    ///
    /// Matches `libspdm_verify_certificate_chain_buffer` semantics:
    /// - Validates `cert_chain_header->length` against the buffer.
    /// - Splits the concatenated DER certificates and rejects trailing bytes.
    /// - If the first certificate in the chain is a self-issued root certificate
    ///   (`issuer == subject`), verifies that its digest matches `root_hash`.
    pub fn parse_with_hash_len(input: &[u8], hash_len: usize) -> Result<Self> {
        if input.is_empty() {
            return Err(SpdmCertError::EmptyInput);
        }

        if input.len() < SPDM_CERT_CHAIN_HEADER_LEN {
            return Err(SpdmCertError::Truncated {
                expected: SPDM_CERT_CHAIN_HEADER_LEN,
                found: input.len(),
            });
        }

        let declared_len = u16::from_le_bytes([input[0], input[1]]) as usize;
        if declared_len > input.len() {
            return Err(SpdmCertError::Truncated {
                expected: declared_len,
                found: input.len(),
            });
        }
        if declared_len <= SPDM_CERT_CHAIN_HEADER_LEN + hash_len {
            return Err(SpdmCertError::InvalidHeaderLength {
                declared: declared_len,
                available: input.len(),
            });
        }

        let chain_buf = &input[..declared_len];
        let payload = &chain_buf[SPDM_CERT_CHAIN_HEADER_LEN..];
        let root_hash = payload[..hash_len].to_vec();
        let certs_der = &payload[hash_len..];

        let cert_slices = split_der_certs(certs_der)?;
        if cert_slices.is_empty() {
            return Err(SpdmCertError::EmptyInput);
        }

        // Validate that each DER slice is a well-formed X.509 certificate
        let first_cert = parse_and_validate_x509_slices(&cert_slices)?;

        // Per DSP0274 and libspdm (`libspdm_verify_certificate_chain_buffer`):
        // If the first certificate in the chain is the Root Certificate itself
        // (`libspdm_is_root_certificate`: self-issued, issuer == subject), its hash
        // must match `RootHash` in the SPDM header. If the first certificate is a
        // subordinate/intermediate certificate, `RootHash` is the digest of the
        // omitted external Root CA.
        if is_self_issued_root(&first_cert) {
            if let Some(computed_hash) = compute_hash(cert_slices[0], hash_len) {
                if computed_hash != root_hash {
                    return Err(SpdmCertError::RootHashMismatch {
                        expected: hex::encode(&root_hash),
                        computed: hex::encode(&computed_hash),
                    });
                }
            }
        }

        let certs = cert_slices.into_iter().map(|s| s.to_vec()).collect();
        Ok(Self {
            has_spdm_header: true,
            root_hash: Some(root_hash),
            certs,
        })
    }

    /// Decodes an SPDM certificate chain blob, raw concatenated DER stream, or PEM chain.
    ///
    /// Automatically detects:
    /// 1. PEM-encoded certificate chains (`-----BEGIN CERTIFICATE-----`)
    /// 2. Raw concatenated ASN.1 DER certificates
    /// 3. SPDM `GET_CERTIFICATE` chain buffers (`Length + Reserved + RootHash + Certificates`)
    ///    with SHA-384 (48B), SHA-256 (32B), or SHA-512 (64B) root hashes.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.is_empty() {
            return Err(SpdmCertError::EmptyInput);
        }

        // 1. Check for PEM-encoded certificates
        if let Some(certs) = try_parse_pem_chain(input)? {
            return Ok(Self {
                has_spdm_header: false,
                root_hash: None,
                certs,
            });
        }

        // 2. If the first byte is 0x30 (SEQUENCE), check if it is a bare concatenated DER stream.
        // Note: an SPDM header with low length byte 0x30 has `Reserved = 0x0000` at bytes 2..4,
        // which is never a valid X.509 DER certificate prefix, so validating X.509 disambiguates.
        if input[0] == 0x30 {
            if let Ok(cert_slices) = split_der_certs(input) {
                if !cert_slices.is_empty() && parse_and_validate_x509_slices(&cert_slices).is_ok() {
                    let certs = cert_slices.into_iter().map(|s| s.to_vec()).collect();
                    return Ok(Self {
                        has_spdm_header: false,
                        root_hash: None,
                        certs,
                    });
                }
            }
        }

        // 3. Parse SPDM header: 2 bytes length (little-endian) + 2 bytes reserved
        if input.len() < SPDM_CERT_CHAIN_HEADER_LEN {
            return Err(SpdmCertError::Truncated {
                expected: SPDM_CERT_CHAIN_HEADER_LEN,
                found: input.len(),
            });
        }

        let declared_len = u16::from_le_bytes([input[0], input[1]]) as usize;
        if declared_len > input.len() {
            return Err(SpdmCertError::Truncated {
                expected: declared_len,
                found: input.len(),
            });
        }

        let mut last_hash_mismatch: Option<SpdmCertError> = None;
        let mut last_err: Option<SpdmCertError> = None;

        for hash_len in SPDM_CANDIDATE_HASH_LENS {
            if declared_len <= SPDM_CERT_CHAIN_HEADER_LEN + hash_len {
                continue;
            }
            let payload = &input[SPDM_CERT_CHAIN_HEADER_LEN..declared_len];
            if payload.get(hash_len).copied() != Some(0x30) {
                continue;
            }

            match Self::parse_with_hash_len(input, hash_len) {
                Ok(chain) => return Ok(chain),
                Err(e @ SpdmCertError::RootHashMismatch { .. }) => {
                    last_hash_mismatch = Some(e);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if let Some(mismatch) = last_hash_mismatch {
            return Err(mismatch);
        }
        if let Some(err) = last_err {
            return Err(err);
        }

        let payload = &input[SPDM_CERT_CHAIN_HEADER_LEN..];
        Err(SpdmCertError::InvalidDerTag {
            offset: SPDM_CERT_CHAIN_HEADER_LEN,
            found: payload.first().copied().unwrap_or(0),
        })
    }

    /// Returns the number of certificates in the chain.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Returns true if the chain contains no certificates.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Returns the root certificate DER bytes.
    pub fn root_cert(&self) -> Option<&[u8]> {
        self.certs.first().map(|v| v.as_slice())
    }

    /// Returns the leaf certificate DER bytes.
    pub fn leaf_cert(&self) -> Option<&[u8]> {
        self.certs.last().map(|v| v.as_slice())
    }
}

fn compute_hash(data: &[u8], hash_len: usize) -> Option<Vec<u8>> {
    match hash_len {
        32 => Some(Sha256::digest(data).to_vec()),
        48 => Some(Sha384::digest(data).to_vec()),
        64 => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

/// Checks whether a certificate is a self-issued root certificate (`issuer == subject`
/// and either BasicConstraints `cA == true` or no BasicConstraints).
/// Matches `libspdm_is_root_certificate` in `DMTF/libspdm`.
fn is_self_issued_root(cert: &X509Certificate) -> bool {
    if cert.issuer() != cert.subject() {
        return false;
    }
    match cert.basic_constraints() {
        Ok(Some(bc)) => bc.value.ca,
        Ok(None) => true,
        Err(_) => false,
    }
}

/// Validates that every slice parses as an X.509 DER certificate with no trailing bytes,
/// returning the first parsed certificate.
fn parse_and_validate_x509_slices<'a>(slices: &[&'a [u8]]) -> Result<X509Certificate<'a>> {
    let mut first = None;
    for (idx, slice) in slices.iter().enumerate() {
        let (rem, cert) = X509Certificate::from_der(slice).map_err(|e| {
            SpdmCertError::X509Error(format!("Certificate #{idx} invalid DER: {e:?}"))
        })?;
        if !rem.is_empty() {
            return Err(SpdmCertError::X509Error(format!(
                "Certificate #{idx} has {} trailing bytes inside DER slice",
                rem.len()
            )));
        }
        if idx == 0 {
            first = Some(cert);
        }
    }
    first.ok_or(SpdmCertError::EmptyInput)
}

/// Attempts to parse PEM-encoded certificate blocks if the input is ASCII PEM text.
fn try_parse_pem_chain(input: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
    let Ok(text) = core::str::from_utf8(input) else {
        return Ok(None);
    };
    let trimmed = text.trim_start();
    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
        return Ok(None);
    }

    let mut certs = Vec::new();
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let mut rest = trimmed;

    while let Some(start_idx) = rest.find(begin_marker) {
        let after_begin = &rest[start_idx + begin_marker.len()..];
        let Some(end_idx) = after_begin.find(end_marker) else {
            return Err(SpdmCertError::X509Error(
                "Missing -----END CERTIFICATE----- marker in PEM input".into(),
            ));
        };
        let b64_body = &after_begin[..end_idx];
        let der = decode_base64_pem(b64_body)?;
        certs.push(der);
        rest = &after_begin[end_idx + end_marker.len()..];
    }

    if certs.is_empty() {
        return Err(SpdmCertError::EmptyInput);
    }

    let slices: Vec<&[u8]> = certs.iter().map(|v| v.as_slice()).collect();
    parse_and_validate_x509_slices(&slices)?;
    Ok(Some(certs))
}

fn decode_base64_pem(b64: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u8;

    for b in b64.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                return Err(SpdmCertError::X509Error(format!(
                    "Invalid base64 character in PEM: {b:#04x}"
                )))
            }
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }

    Ok(out)
}

/// Splits a concatenated ASN.1 DER blob into individual certificate slices.
pub fn split_der_certs(blob: &[u8]) -> Result<Vec<&[u8]>> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < blob.len() {
        if blob[offset] != 0x30 {
            return Err(SpdmCertError::InvalidDerTag {
                offset,
                found: blob[offset],
            });
        }

        let (content_len, header_len) = parse_der_length(&blob[offset + 1..])?;
        let total_len = 1 + header_len + content_len;

        if offset + total_len > blob.len() {
            return Err(SpdmCertError::Truncated {
                expected: offset + total_len,
                found: blob.len(),
            });
        }

        certs.push(&blob[offset..offset + total_len]);
        offset += total_len;
    }

    Ok(certs)
}

/// Parses ASN.1 DER length field. Returns (content_length, header_bytes_consumed).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(SpdmCertError::DerLengthError("Truncated DER length".into()));
    }

    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }

    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
        return Err(SpdmCertError::DerLengthError(
            "Invalid or unsupported multi-byte DER length".into(),
        ));
    }

    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | (data[1 + i] as usize);
    }

    Ok((len, 1 + num_bytes))
}
