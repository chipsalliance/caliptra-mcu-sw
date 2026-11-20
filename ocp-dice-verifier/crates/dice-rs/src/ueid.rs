// Licensed under the Apache-2.0 license

//! TCG DICE `DiceUeid` structure and decoding.
//!
//! Reference: TCG DICE Attestation Architecture v1.2, Section 8.1.

use crate::error::{DiceError, Result};

/// TCG DICE `DiceUeid` extension.
///
/// Contains the Universal Entity Identifier (UEID) for device or context identification.
#[derive(Debug, Clone, PartialEq, Eq, asn1::Asn1Read)]
pub struct Ueid<'a> {
    /// Raw UEID byte payload.
    pub ueid: &'a [u8],
}

impl<'a> Ueid<'a> {
    /// Parses a `Ueid` from ASN.1 DER-encoded bytes.
    pub fn from_der(der: &'a [u8]) -> Result<Self> {
        asn1::parse_single::<Self>(der).map_err(|e| DiceError::Asn1(format!("{:?}", e)))
    }
}
