// Licensed under the Apache-2.0 license

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SpdmCertError {
    #[error("Empty certificate chain input")]
    EmptyInput,

    #[error("Chain buffer truncated: expected {expected} bytes, found {found}")]
    Truncated { expected: usize, found: usize },

    #[error("Chain header length {declared} exceeds buffer length {available} or is too small")]
    InvalidHeaderLength { declared: usize, available: usize },

    #[error("Invalid DER SEQUENCE at offset {offset}: expected tag 0x30, found {found:#04x}")]
    InvalidDerTag { offset: usize, found: u8 },

    #[error("Failed to parse DER length: {0}")]
    DerLengthError(String),

    #[error("X.509 parsing failed: {0}")]
    X509Error(String),

    #[error("ASN.1 parsing failed: {0}")]
    Asn1Error(String),

    #[error("DICE extension error: {0}")]
    DiceError(#[from] dice_rs::error::DiceError),

    #[error("Root hash mismatch: expected {expected}, computed {computed}")]
    RootHashMismatch { expected: String, computed: String },
}

pub type Result<T> = std::result::Result<T, SpdmCertError>;
