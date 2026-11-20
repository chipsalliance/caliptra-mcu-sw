// Licensed under the Apache-2.0 license

//! TCG DICE `DiceTcbInfo` structure and decoding.
//!
//! Reference: TCG DICE Attestation Architecture v1.2, Section 8.1.

use crate::error::{DiceError, Result};

/// Firmware identifier containing a hash algorithm OID and digest.
#[derive(Debug, Clone, PartialEq, Eq, asn1::Asn1Read)]
pub struct Fwid<'a> {
    /// Hash algorithm OID (e.g., SHA-384, SHA-256).
    pub hash_alg: asn1::ObjectIdentifier,
    /// Digest bytes.
    pub digest: &'a [u8],
}

/// Integrity register entry representing cumulative or platform registers.
#[derive(Clone, PartialEq, asn1::Asn1Read)]
pub struct IntegrityRegister<'a> {
    #[implicit(0)]
    pub register_name: Option<asn1::IA5String<'a>>,
    #[implicit(1)]
    pub register_num: Option<u64>,
    #[implicit(2)]
    pub register_digests: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
}

/// TCG DICE `DiceTcbInfo` sequence.
///
/// Encapsulates the measurements, versioning, and operational status of a single TCB layer.
#[derive(Clone, PartialEq, asn1::Asn1Read)]
pub struct TcbInfo<'a> {
    /// Vendor of the component.
    #[implicit(0)]
    pub vendor: Option<asn1::Utf8String<'a>>,

    /// Hardware or device model name.
    #[implicit(1)]
    pub model: Option<asn1::Utf8String<'a>>,

    /// Firmware or software version string.
    #[implicit(2)]
    pub version: Option<asn1::Utf8String<'a>>,

    /// Security Version Number (SVN).
    #[implicit(3)]
    pub svn: Option<u64>,

    /// Layer index in the DICE derivation chain.
    #[implicit(4)]
    pub layer: Option<u64>,

    /// Index of the component within the layer.
    #[implicit(5)]
    pub index: Option<u64>,

    /// Sequence of firmware identifiers / code measurements.
    #[implicit(6)]
    pub fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,

    /// Operational flags (e.g. debug mode).
    #[implicit(7)]
    pub flags: Option<asn1::BitString<'a>>,

    /// Vendor-specific information (or target locality in DPE).
    #[implicit(8)]
    pub vendor_info: Option<&'a [u8]>,

    /// TCI measurement type (4-byte identifier in DPE).
    #[implicit(9)]
    pub tci_type: Option<&'a [u8]>,

    /// Operational flags mask.
    #[implicit(10)]
    pub operational_flags_mask: Option<asn1::BitString<'a>>,

    /// Integrity registers (cumulative measurements).
    #[implicit(11)]
    pub integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
}

impl<'a> TcbInfo<'a> {
    /// Parses a `TcbInfo` structure from ASN.1 DER-encoded bytes.
    pub fn from_der(der: &'a [u8]) -> Result<Self> {
        asn1::parse_single::<Self>(der).map_err(|e| DiceError::Asn1(format!("{:?}", e)))
    }
}
