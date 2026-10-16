// Licensed under the Apache-2.0 license

//! DMTF SPDM Certificate Chain decoder.
//!
//! Handles SPDM certificate chain unpacking, root hash verification,
//! and splitting concatenated ASN.1 DER certificates.

use crate::error::{Result, SpdmCertError};
use sha2::{Digest, Sha256, Sha384};

/// Minimum SPDM cert chain header length:
/// 2 bytes `Length` + 2 bytes `Reserved` = 4 bytes.
pub const SPDM_CERT_CHAIN_HEADER_LEN: usize = 4;

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
    /// Decodes an SPDM certificate chain blob.
    ///
    /// Automatically detects whether the input has an SPDM header
    /// (Length + Reserved + RootHash) or is a raw concatenated DER stream.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.is_empty() {
            return Err(SpdmCertError::EmptyInput);
        }

        // If the first byte is 0x30 (SEQUENCE), it is a bare concatenated DER stream
        if input[0] == 0x30 {
            let cert_slices = split_der_certs(input)?;
            let certs = cert_slices.into_iter().map(|s| s.to_vec()).collect();
            return Ok(Self {
                has_spdm_header: false,
                root_hash: None,
                certs,
            });
        }

        // Otherwise parse SPDM header: 2 bytes length (little-endian) + 2 bytes reserved
        if input.len() < SPDM_CERT_CHAIN_HEADER_LEN {
            return Err(SpdmCertError::Truncated {
                expected: SPDM_CERT_CHAIN_HEADER_LEN,
                found: input.len(),
            });
        }

        let declared_len = u16::from_le_bytes([input[0], input[1]]) as usize;
        let payload = &input[SPDM_CERT_CHAIN_HEADER_LEN..];

        // Root hash length can be SHA-384 (48 bytes) or SHA-256 (32 bytes)
        // Detect which hash is used by checking if cert starts at offset 48 or offset 32
        let (hash_len, der_offset) = if payload.len() >= 48 && payload[48] == 0x30 {
            (48, 48)
        } else if payload.len() >= 32 && payload[32] == 0x30 {
            (32, 32)
        } else {
            return Err(SpdmCertError::InvalidDerTag {
                offset: SPDM_CERT_CHAIN_HEADER_LEN,
                found: payload.first().copied().unwrap_or(0),
            });
        };

        let root_hash = payload[..hash_len].to_vec();
        let certs_der = &payload[der_offset..];
        let cert_slices = split_der_certs(certs_der)?;
        let certs: Vec<Vec<u8>> = cert_slices.into_iter().map(|s| s.to_vec()).collect();

        // Verify root certificate hash if root cert exists
        if let Some(root_cert) = certs.first() {
            let computed_hash = if hash_len == 48 {
                Sha384::digest(root_cert).to_vec()
            } else {
                Sha256::digest(root_cert).to_vec()
            };

            if computed_hash != root_hash {
                return Err(SpdmCertError::RootHashMismatch {
                    expected: hex::encode(&root_hash),
                    computed: hex::encode(&computed_hash),
                });
            }
        }

        let _ = declared_len; // May be used for padding verification

        Ok(Self {
            has_spdm_header: true,
            root_hash: Some(root_hash),
            certs,
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
