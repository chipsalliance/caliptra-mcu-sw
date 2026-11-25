// Licensed under the Apache-2.0 license

//! TCG DICE `DiceMultiTcbInfo` structure and decoding.
//!
//! Reference: TCG DICE Attestation Architecture v1.2, Section 8.1.

use crate::error::{DiceError, Result};
use crate::tcb_info::TcbInfo;

/// TCG DICE `DiceMultiTcbInfo` extension.
///
/// Encapsulates a sequence of `DiceTcbInfo` structures representing composite
/// or multi-component measurements (e.g. Caliptra FMC fuses + firmware, or DPE TCI chain).
#[derive(Clone, PartialEq)]
pub struct MultiTcbInfo<'a> {
    /// List of individual TCB measurement nodes.
    pub entries: asn1::SequenceOf<'a, TcbInfo<'a>>,
}

impl<'a> MultiTcbInfo<'a> {
    /// Parses a `MultiTcbInfo` sequence from ASN.1 DER-encoded bytes.
    pub fn from_der(der: &'a [u8]) -> Result<Self> {
        let entries = asn1::parse_single::<asn1::SequenceOf<'a, TcbInfo<'a>>>(der)
            .map_err(|e| DiceError::Asn1(format!("{:?}", e)))?;
        Ok(Self { entries })
    }

    /// Returns an iterator over the TCB info entries.
    pub fn iter(&self) -> impl Iterator<Item = TcbInfo<'a>> {
        self.entries.clone()
    }
}
